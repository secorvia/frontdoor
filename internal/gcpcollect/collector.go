// Package gcpcollect reads federated trust out of GCP projects.
//
// READ-ONLY. Every GCP call in this package is a List, Get or Search. There is
// no code path that mutates anything. A denied call is recorded in
// Result.Unreadable and the scan continues.
//
// The GCP shape of a "door" is not a trust policy but a pair: a workload
// identity provider says which outside identities exist, and a service account
// IAM binding says which of them may become that service account. Neither half
// means anything alone, so this collector always joins them.
package gcpcollect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	crm "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/secorvia/frontdoor/internal/model"
)

// Options configure a GCP scan.
type Options struct {
	// Projects to scan. Empty means fall back to the environment, and then to
	// AllProjects.
	Projects []string
	// AllProjects searches every project the caller can see. Off by default:
	// on a large organization that is thousands of API calls nobody asked for.
	AllProjects bool
	// CredentialsFile overrides Application Default Credentials.
	CredentialsFile string
	Concurrency     int
	SkipKeys        bool
}

func (o Options) concurrency() int {
	if o.Concurrency > 0 {
		return o.Concurrency
	}
	return 6
}

// Collector holds the GCP clients.
type Collector struct {
	opts Options
	iam  *iam.Service
	crm  *crm.Service

	mu sync.Mutex
	// edges are the service-account impersonation links found while walking
	edges []model.Hop
}

// ImpersonationEdges returns the service-account impersonation links found by
// the scan. FD030 walks these to find chains that end somewhere privileged.
func (c *Collector) ImpersonationEdges() []model.Hop {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.Hop(nil), c.edges...)
}

// New builds a Collector from Application Default Credentials: the
// GOOGLE_APPLICATION_CREDENTIALS file, gcloud's application-default login, or
// the metadata server. frontdoor never reads credentials itself.
func New(ctx context.Context, opts Options) (*Collector, error) {
	clientOpts := []option.ClientOption{
		option.WithScopes("https://www.googleapis.com/auth/cloud-platform.read-only"),
	}
	if opts.CredentialsFile != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	iamSvc, err := iam.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("no usable GCP credentials found (checked GOOGLE_APPLICATION_CREDENTIALS, gcloud application-default, metadata server): %w", err)
	}
	crmSvc, err := crm.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("cloud resource manager: %w", err)
	}

	return &Collector{opts: opts, iam: iamSvc, crm: crmSvc}, nil
}

// Collect runs the whole GCP pass and appends to res.
func (c *Collector) Collect(ctx context.Context, res *model.Result) error {
	projects, err := c.resolveProjects(ctx, res)
	if err != nil {
		return err
	}
	if len(projects) == 0 {
		return errors.New("no GCP project to scan: pass --gcp-project, set GOOGLE_CLOUD_PROJECT, or pass --gcp-all-projects")
	}

	for _, p := range projects {
		res.Accounts = append(res.Accounts, model.Account{
			Provider: model.ProviderGCP, ID: p.id, Name: p.name, Scanned: true,
		})
		c.collectProject(ctx, res, p)
	}
	return nil
}

type project struct {
	id   string
	name string
}

// resolveProjects decides what to scan, in a fixed order of preference so the
// same command always scans the same thing.
func (c *Collector) resolveProjects(ctx context.Context, res *model.Result) ([]project, error) {
	if len(c.opts.Projects) > 0 {
		out := make([]project, 0, len(c.opts.Projects))
		for _, id := range c.opts.Projects {
			out = append(out, project{id: id, name: c.projectName(ctx, res, id)})
		}
		return out, nil
	}

	if !c.opts.AllProjects {
		for _, env := range []string{"GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "CLOUDSDK_CORE_PROJECT"} {
			if id := strings.TrimSpace(os.Getenv(env)); id != "" {
				return []project{{id: id, name: c.projectName(ctx, res, id)}}, nil
			}
		}
		return nil, nil
	}

	var out []project
	err := c.crm.Projects.Search().Pages(ctx, func(page *crm.SearchProjectsResponse) error {
		for _, p := range page.Projects {
			if p.State != "ACTIVE" {
				continue
			}
			out = append(out, project{id: p.ProjectId, name: p.DisplayName})
		}
		return nil
	})
	if err != nil {
		c.note(res, "", "cloudresourcemanager.projects.search", "", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

func (c *Collector) projectName(ctx context.Context, res *model.Result, id string) string {
	p, err := c.crm.Projects.Get("projects/" + id).Context(ctx).Do()
	if err != nil {
		c.note(res, id, "cloudresourcemanager.projects.get", id, err)
		return ""
	}
	return p.DisplayName
}

// collectProject is one project's whole pass.
func (c *Collector) collectProject(ctx context.Context, res *model.Result, p project) {
	providers := c.collectPools(ctx, res, p)
	projectRoles := c.collectProjectIAM(ctx, res, p)
	c.collectServiceAccounts(ctx, res, p, providers, projectRoles)
}

// collectPools reads the workload identity pools and their providers. A pool
// with no provider admits nobody; a provider with no binding is dead weight.
func (c *Collector) collectPools(ctx context.Context, res *model.Result, p project) map[string][]*model.IdentityProvider {
	byPool := map[string][]*model.IdentityProvider{}
	parent := "projects/" + p.id + "/locations/global"

	err := c.iam.Projects.Locations.WorkloadIdentityPools.List(parent).Pages(ctx,
		func(page *iam.ListWorkloadIdentityPoolsResponse) error {
			for _, pool := range page.WorkloadIdentityPools {
				c.collectProviders(ctx, res, p, pool, byPool)
			}
			return nil
		})
	if err != nil {
		c.note(res, p.id, "iam.workloadIdentityPools.list", parent, err)
	}
	return byPool
}

func (c *Collector) collectProviders(ctx context.Context, res *model.Result, p project, pool *iam.WorkloadIdentityPool, byPool map[string][]*model.IdentityProvider) {
	err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.List(pool.Name).Pages(ctx,
		func(page *iam.ListWorkloadIdentityPoolProvidersResponse) error {
			for _, prov := range page.WorkloadIdentityPoolProviders {
				ip := model.IdentityProvider{
					Provider:           model.ProviderGCP,
					AccountID:          p.id,
					ARN:                prov.Name,
					Pool:               pool.Name,
					AttributeCondition: prov.AttributeCondition,
					AttributeMapping:   prov.AttributeMapping,
					Disabled:           prov.Disabled || pool.Disabled,
					ReferencedBy:       []string{},
				}
				switch {
				case prov.Oidc != nil:
					ip.Type = model.PrincipalOIDC
					ip.URL = prov.Oidc.IssuerUri
					ip.Audiences = prov.Oidc.AllowedAudiences
				case prov.Saml != nil:
					ip.Type = model.PrincipalSAML
					ip.EntityID = samlEntityID(prov.Saml.IdpMetadataXml)
					ip.URL = ip.EntityID
				case prov.Aws != nil:
					ip.Type = model.PrincipalCrossAccount
					ip.URL = "AWS account " + prov.Aws.AccountId
					ip.EntityID = prov.Aws.AccountId
				default:
					ip.Type = model.PrincipalOIDC
				}

				res.IdentityProviders = append(res.IdentityProviders, ip)
				snapshot := ip
				byPool[pool.Name] = append(byPool[pool.Name], &snapshot)
			}
			return nil
		})
	if err != nil {
		c.note(res, p.id, "iam.workloadIdentityPools.providers.list", pool.Name, err)
	}

	// A pool with no providers still shows up, so an operator can see it and
	// delete it.
	if len(byPool[pool.Name]) == 0 {
		res.IdentityProviders = append(res.IdentityProviders, model.IdentityProvider{
			Provider: model.ProviderGCP, AccountID: p.id, ARN: pool.Name,
			Pool: pool.Name, Type: model.PrincipalOIDC, Disabled: pool.Disabled,
			ReferencedBy: []string{},
		})
	}
}

// collectProjectIAM reads the project policy. It does two jobs: it finds
// external principals bound at the project level, and it tells us which roles
// each service account holds, which is how we know whether reaching one
// matters.
func (c *Collector) collectProjectIAM(ctx context.Context, res *model.Result, p project) map[string][]string {
	roles := map[string][]string{}
	resource := "projects/" + p.id

	policy, err := c.crm.Projects.GetIamPolicy(resource, &crm.GetIamPolicyRequest{
		Options: &crm.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Context(ctx).Do()
	if err != nil {
		c.note(res, p.id, "resourcemanager.projects.getIamPolicy", resource, err)
		return roles
	}

	for _, b := range policy.Bindings {
		for _, raw := range b.Members {
			m := ParseMember(raw)
			if m.Kind == MemberServiceAccount {
				roles[m.Email] = append(roles[m.Email], b.Role)
			}
			if !isExternalMember(m, p.id) {
				continue
			}
			// An external principal bound directly at the project level is a
			// door into everything the role covers, with no service account
			// in between.
			d := c.doorFromBinding(p, resource, "project "+p.id, fromCRMBinding(b), m, nil, nil)
			d.GrantedActions = []string{b.Role}
			if why, priv := ClassifyRole(b.Role); priv {
				d.IsPrivileged = true
				d.PrivilegeReasons = []string{why}
			}
			res.Doors = append(res.Doors, d)
		}
	}
	return roles
}

// collectServiceAccounts is the main pass: every service account, its IAM
// policy, and the doors and impersonation edges that policy creates.
func (c *Collector) collectServiceAccounts(ctx context.Context, res *model.Result, p project, byPool map[string][]*model.IdentityProvider, projectRoles map[string][]string) {
	var accounts []*iam.ServiceAccount
	err := c.iam.Projects.ServiceAccounts.List("projects/"+p.id).Pages(ctx,
		func(page *iam.ListServiceAccountsResponse) error {
			accounts = append(accounts, page.Accounts...)
			return nil
		})
	if err != nil {
		c.note(res, p.id, "iam.serviceAccounts.list", "projects/"+p.id, err)
		return
	}

	type saResult struct {
		doors []model.Door
		edges []model.Hop
		keys  []model.AccessKey
	}
	results := make([]saResult, len(accounts))

	sem := make(chan struct{}, c.opts.concurrency())
	var wg sync.WaitGroup
	for i, sa := range accounts {
		wg.Add(1)
		go func(i int, sa *iam.ServiceAccount) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			doors, edges := c.serviceAccountPolicy(ctx, res, p, sa, byPool, projectRoles)
			var keys []model.AccessKey
			if !c.opts.SkipKeys {
				keys = c.serviceAccountKeys(ctx, res, p, sa)
			}
			results[i] = saResult{doors: doors, edges: edges, keys: keys}
		}(i, sa)
	}
	wg.Wait()

	for _, r := range results {
		res.Doors = append(res.Doors, r.doors...)
		res.AccessKeys = append(res.AccessKeys, r.keys...)
		c.edges = append(c.edges, r.edges...)
	}

	// Every service account becomes a graph node, whether or not anything
	// federates into it. The one holding roles/owner at the end of a chain
	// usually has no door of its own, and leaving it out of the index is how a
	// chain ends up reported as harmless.
	for _, sa := range accounts {
		roles := projectRoles[sa.Email]
		privileged, reasons := classifyRoles(roles)
		res.Principals = append(res.Principals, model.Principal{
			Provider:  model.ProviderGCP,
			NodeID:    sa.Email,
			Name:      orEmpty(sa.DisplayName, sa.Email),
			AccountID: p.id,
			// UniqueId is the number an AWS trust policy carries when it
			// federates to Google. It is the only join between the two clouds.
			UniqueID:   sa.UniqueId,
			Grants:     roles,
			Privileged: privileged,
			Reasons:    reasons,
		})
	}
}

func (c *Collector) serviceAccountPolicy(ctx context.Context, res *model.Result, p project, sa *iam.ServiceAccount, byPool map[string][]*model.IdentityProvider, projectRoles map[string][]string) ([]model.Door, []model.Hop) {
	policy, err := c.iam.Projects.ServiceAccounts.GetIamPolicy(sa.Name).
		OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		c.note(res, p.id, "iam.serviceAccounts.getIamPolicy", sa.Email, err)
		return nil, nil
	}

	roles := projectRoles[sa.Email]
	privileged, reasons := classifyRoles(roles)

	var doors []model.Door
	var edges []model.Hop

	for _, b := range policy.Bindings {
		for _, raw := range b.Members {
			m := ParseMember(raw)

			// SA -> SA impersonation: an edge in the chain graph, not a door.
			if m.Kind == MemberServiceAccount && IsImpersonation(b.Role) {
				edges = append(edges, model.Hop{
					Kind:     model.EdgeImpersonation,
					From:     m.Email,
					To:       sa.Email,
					Via:      b.Role,
					Provider: model.ProviderGCP,
					Detail:   "can " + ImpersonationVerb(b.Role) + " " + sa.Email,
				})
				continue
			}
			if !isExternalMember(m, p.id) {
				continue
			}

			providers := byPool[m.Pool]
			if len(providers) == 0 {
				providers = []*model.IdentityProvider{nil}
			}
			for _, prov := range providers {
				d := c.doorFromBinding(p, sa.Name, sa.Email, fromIAMBinding(b), m, prov, roles)
				d.IsPrivileged = privileged
				d.PrivilegeReasons = reasons
				doors = append(doors, d)

				if prov != nil {
					c.mu.Lock()
					for i := range res.IdentityProviders {
						if res.IdentityProviders[i].ARN == prov.ARN {
							res.IdentityProviders[i].ReferencedBy =
								appendUnique(res.IdentityProviders[i].ReferencedBy, sa.Email)
						}
					}
					c.mu.Unlock()
				}
			}
		}
	}
	return doors, edges
}

// doorFromBinding builds the Door for one (binding, member, provider) triple.
func (c *Collector) doorFromBinding(p project, resource, displayName string, b iamBinding, m Member, prov *model.IdentityProvider, roles []string) model.Door {
	issuer := ""
	var conds []model.Condition

	if prov != nil {
		issuer = prov.URL
		if prov.Type == model.PrincipalSAML && prov.EntityID != "" {
			issuer = prov.EntityID
		}
		conds = append(conds, ParseAttributeCondition(prov.AttributeCondition)...)
		for _, aud := range prov.Audiences {
			conds = append(conds, model.Condition{Operator: "equals", Key: "aud", Values: []string{aud}})
		}
	}
	// An IAM condition on the binding itself narrows it further.
	if b.Condition != nil && b.Condition.Expression != "" {
		conds = append(conds, ParseAttributeCondition(b.Condition.Expression)...)
		conds = append(conds, model.Condition{
			Operator: "iamCondition", Key: orEmpty(b.Condition.Title, "binding condition"),
			Values: []string{b.Condition.Expression},
		})
	}

	d := model.Door{
		Provider:        model.ProviderGCP,
		AccountID:       p.id,
		ResourceARN:     resource,
		ResourceName:    displayName,
		NodeID:          displayName,
		Issuer:          issuer,
		Conditions:      conds,
		ExternalParties: []model.ExternalParty{PartyFor(m, prov)},
		TrustActions:    []string{b.Role},
		GrantedActions:  roles,
	}
	if prov != nil {
		d.ProviderARN = prov.ARN
		d.Audiences = prov.Audiences
	}

	switch {
	case m.Kind == MemberFederated && prov != nil && prov.Type == model.PrincipalSAML:
		d.PrincipalType = model.PrincipalSAML
	case m.Kind == MemberFederated && prov != nil && prov.Type == model.PrincipalCrossAccount:
		d.PrincipalType = model.PrincipalCrossAccount
	case m.Kind == MemberFederated:
		d.PrincipalType = model.PrincipalOIDC
	case m.Kind == MemberServiceAccount:
		d.PrincipalType = model.PrincipalCrossAccount
	default:
		d.PrincipalType = model.PrincipalCrossAccount
	}
	return d
}

func (c *Collector) serviceAccountKeys(ctx context.Context, res *model.Result, p project, sa *iam.ServiceAccount) []model.AccessKey {
	out, err := c.iam.Projects.ServiceAccounts.Keys.List(sa.Name).
		KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		c.note(res, p.id, "iam.serviceAccountKeys.list", sa.Email, err)
		return nil
	}

	var keys []model.AccessKey
	for _, k := range out.Keys {
		key := model.AccessKey{
			Provider:    model.ProviderGCP,
			AccountID:   p.id,
			UserName:    sa.Email,
			UserARN:     sa.Name,
			AccessKeyID: keyID(k.Name),
			Status:      "Active",
		}
		if k.Disabled {
			key.Status = "Inactive"
		}
		if t, err := time.Parse(time.RFC3339, k.ValidAfterTime); err == nil {
			key.CreatedAt = &t
		}
		// GCP does not report last-used for service account keys through this
		// API, so LastUsed stays nil and the rules must not read that as
		// "never used".
		keys = append(keys, key)
	}
	return keys
}

// --- helpers -----------------------------------------------------------------

// iamBinding is the shape both cloudresourcemanager and iam bindings share,
// so doorFromBinding does not need to be written twice.
type iamBinding struct {
	Role      string
	Members   []string
	Condition *iamExpr
}

type iamExpr struct {
	Title      string
	Expression string
}

// The two GCP APIs return structurally identical bindings under different
// types, so both are normalised here rather than writing doorFromBinding twice.
func fromCRMBinding(b *crm.Binding) iamBinding {
	out := iamBinding{Role: b.Role, Members: b.Members}
	if b.Condition != nil && b.Condition.Expression != "" {
		out.Condition = &iamExpr{Title: b.Condition.Title, Expression: b.Condition.Expression}
	}
	return out
}

func fromIAMBinding(b *iam.Binding) iamBinding {
	out := iamBinding{Role: b.Role, Members: b.Members}
	if b.Condition != nil && b.Condition.Expression != "" {
		out.Condition = &iamExpr{Title: b.Condition.Title, Expression: b.Condition.Expression}
	}
	return out
}

// isExternalMember decides whether a member is outside the project. A service
// account belonging to this project is not a door from outside; one from
// another project is.
func isExternalMember(m Member, projectID string) bool {
	switch m.Kind {
	case MemberFederated, MemberAllUsers, MemberDomain:
		return true
	case MemberServiceAccount:
		return m.Project != "" && m.Project != projectID
	case MemberUser, MemberGroup:
		// A human is not a federated workload, but a user bound directly into
		// a project is still a way in that nobody inventories.
		return true
	}
	return false
}

func classifyRoles(roles []string) (bool, []string) {
	var reasons []string
	privileged := false
	for _, r := range roles {
		if why, ok := ClassifyRole(r); ok {
			privileged = true
			reasons = append(reasons, why)
		}
	}
	sort.Strings(reasons)
	return privileged, reasons
}

func samlEntityID(metadata string) string {
	for _, marker := range []string{`entityID="`, `entityID='`} {
		if i := strings.Index(metadata, marker); i >= 0 {
			rest := metadata[i+len(marker):]
			if j := strings.IndexAny(rest, `"'`); j > 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

func keyID(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func appendUnique(list []string, s string) []string {
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	return append(list, s)
}

func orEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// note records one thing the scan could not read.
func (c *Collector) note(res *model.Result, projectID, operation, resource string, err error) {
	code := ""
	denied := false
	msg := err.Error()

	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		code = fmt.Sprintf("%d", gerr.Code)
		msg = gerr.Message
		denied = gerr.Code == http.StatusForbidden || gerr.Code == http.StatusUnauthorized
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	res.AddUnreadable(model.Unreadable{
		Provider:  model.ProviderGCP,
		AccountID: projectID,
		Operation: operation,
		Resource:  resource,
		Code:      code,
		Message:   msg,
		Denied:    denied,
	})
}
