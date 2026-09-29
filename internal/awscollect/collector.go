// Package awscollect reads federated trust out of an AWS account.
//
// READ-ONLY. Every AWS call in this package is a List, Get or Describe.
// There is no code path that mutates anything, and there is no network egress
// other than to AWS. A denied call is recorded in Result.Unreadable and the
// scan continues; it never aborts the run and never guesses at what it could
// not see.
package awscollect

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/secorvia/frontdoor/internal/model"
)

// Options configure a scan.
type Options struct {
	Profile        string
	Region         string
	Concurrency    int  // parallel per-role policy reads
	IncludeService bool // keep AWS service-principal trusts
	SkipAccessKeys bool
	SkipOrg        bool
}

func (o Options) concurrency() int {
	if o.Concurrency > 0 {
		return o.Concurrency
	}
	return 8
}

// Collector holds the AWS clients for one account.
type Collector struct {
	opts Options
	iam  *iam.Client
	sts  *sts.Client
	org  *organizations.Client

	mu sync.Mutex // guards writes into the shared Result

	// edges are the same-account assume-role links found while parsing trust
	// policies. They are not doors, but they are how a chain continues.
	edges []model.Hop
}

// AssumeEdges returns the same-account assume-role links found by the scan.
func (c *Collector) AssumeEdges() []model.Hop {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.Hop(nil), c.edges...)
}

// New builds a Collector from the standard AWS credential chain: environment
// variables, shared config and credentials files, SSO, and instance metadata.
// frontdoor never reads credentials itself and never writes them anywhere.
func New(ctx context.Context, opts Options) (*Collector, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		// IAM is a global service but the SDK still needs a region to sign.
		awsconfig.WithDefaultRegion("us-east-1"),
		awsconfig.WithRetryMaxAttempts(5),
	}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(opts.Profile))
	}
	if opts.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opts.Region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("no usable AWS credentials found (checked env, shared config, SSO, IMDS): %w", err)
	}

	return &Collector{
		opts: opts,
		iam:  iam.NewFromConfig(cfg),
		sts:  sts.NewFromConfig(cfg),
		org:  organizations.NewFromConfig(cfg),
	}, nil
}

// Collect runs the whole AWS pass and appends to res.
func (c *Collector) Collect(ctx context.Context, res *model.Result) error {
	account, err := c.identify(ctx, res)
	if err != nil {
		return err
	}

	providers := c.collectProviders(ctx, res, account.ID)
	c.collectOrg(ctx, res, account)
	doors := c.collectRoles(ctx, res, account.ID, providers)

	// A provider nothing references is a door left standing with no room
	// behind it - still usable, still forgotten. Phase 2 FD021 needs this.
	byARN := make(map[string][]string)
	for _, d := range doors {
		if d.ProviderARN != "" {
			byARN[d.ProviderARN] = append(byARN[d.ProviderARN], d.ResourceARN)
		}
	}
	for i := range res.IdentityProviders {
		p := &res.IdentityProviders[i]
		refs := byARN[p.ARN]
		sort.Strings(refs)
		p.ReferencedBy = dedupe(refs)
	}

	res.Doors = append(res.Doors, doors...)

	if !c.opts.SkipAccessKeys {
		c.collectAccessKeys(ctx, res, account.ID)
	}
	return nil
}

// identify resolves which account we are actually pointed at. Getting this
// wrong would make every cross-account trust look external, so it is fatal.
func (c *Collector) identify(ctx context.Context, res *model.Result) (model.Account, error) {
	id, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return model.Account{}, fmt.Errorf("sts:GetCallerIdentity failed, cannot determine which account to scan: %w", err)
	}
	acct := model.Account{
		Provider:  model.ProviderAWS,
		ID:        aws.ToString(id.Account),
		CallerARN: aws.ToString(id.Arn),
		Scanned:   true,
	}

	if out, err := c.iam.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{}); err != nil {
		c.note(res, acct.ID, "iam:ListAccountAliases", "", err)
	} else if len(out.AccountAliases) > 0 {
		acct.Alias = out.AccountAliases[0]
		acct.Name = out.AccountAliases[0]
	}

	res.Accounts = append(res.Accounts, acct)
	return acct, nil
}

// collectProviders reads the registered OIDC and SAML providers.
func (c *Collector) collectProviders(ctx context.Context, res *model.Result, accountID string) map[string]*model.IdentityProvider {
	index := map[string]*model.IdentityProvider{}

	if out, err := c.iam.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{}); err != nil {
		c.note(res, accountID, "iam:ListOpenIDConnectProviders", "", err)
	} else {
		for _, entry := range out.OpenIDConnectProviderList {
			arn := aws.ToString(entry.Arn)
			p := model.IdentityProvider{
				Provider: model.ProviderAWS, AccountID: accountID,
				ARN: arn, Type: model.PrincipalOIDC, ReferencedBy: []string{},
			}
			detail, err := c.iam.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: entry.Arn,
			})
			if err != nil {
				c.note(res, accountID, "iam:GetOpenIDConnectProvider", arn, err)
			} else {
				p.URL = aws.ToString(detail.Url)
				p.Audiences = detail.ClientIDList
				p.Thumbprints = detail.ThumbprintList
				p.CreatedAt = detail.CreateDate
			}
			res.IdentityProviders = append(res.IdentityProviders, p)
			// Index a copy: append may reallocate the slice, so a pointer
			// into its backing array would go stale.
			snapshot := p
			index[arn] = &snapshot
		}
	}

	if out, err := c.iam.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{}); err != nil {
		c.note(res, accountID, "iam:ListSAMLProviders", "", err)
	} else {
		for _, entry := range out.SAMLProviderList {
			arn := aws.ToString(entry.Arn)
			p := model.IdentityProvider{
				Provider: model.ProviderAWS, AccountID: accountID,
				ARN: arn, Type: model.PrincipalSAML,
				CreatedAt: entry.CreateDate, ValidUntil: entry.ValidUntil,
				ReferencedBy: []string{},
			}
			detail, err := c.iam.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: entry.Arn})
			if err != nil {
				c.note(res, accountID, "iam:GetSAMLProvider", arn, err)
			} else {
				// Keep only the entityID. The metadata document also carries
				// signing certificates and is never stored or printed.
				p.EntityID = samlEntityID(aws.ToString(detail.SAMLMetadataDocument))
				if detail.ValidUntil != nil {
					p.ValidUntil = detail.ValidUntil
				}
			}
			res.IdentityProviders = append(res.IdentityProviders, p)
			// Index a copy: append may reallocate the slice, so a pointer
			// into its backing array would go stale.
			snapshot := p
			index[arn] = &snapshot
		}
	}

	return index
}

var entityIDRe = regexp.MustCompile(`entityID=["']([^"']+)["']`)

func samlEntityID(metadata string) string {
	if m := entityIDRe.FindStringSubmatch(metadata); len(m) == 2 {
		return m[1]
	}
	return ""
}

// collectOrg learns the organization layout so a cross-account trust to a
// sibling account can be told apart from one to a stranger. Frequently denied
// from a member account, which is expected, not an error.
func (c *Collector) collectOrg(ctx context.Context, res *model.Result, self model.Account) {
	if c.opts.SkipOrg {
		return
	}
	orgID := ""
	if out, err := c.org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{}); err != nil {
		c.note(res, self.ID, "organizations:DescribeOrganization", "", err)
	} else if out.Organization != nil {
		orgID = aws.ToString(out.Organization.Id)
	}

	pager := organizations.NewListAccountsPaginator(c.org, &organizations.ListAccountsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			c.note(res, self.ID, "organizations:ListAccounts", "", err)
			return
		}
		for _, a := range page.Accounts {
			id := aws.ToString(a.Id)
			if id == self.ID {
				for i := range res.Accounts {
					if res.Accounts[i].ID == id {
						res.Accounts[i].InOrg = true
						res.Accounts[i].OrgID = orgID
						if res.Accounts[i].Name == "" {
							res.Accounts[i].Name = aws.ToString(a.Name)
						}
					}
				}
				continue
			}
			res.Accounts = append(res.Accounts, model.Account{
				Provider: model.ProviderAWS, ID: id,
				Name: aws.ToString(a.Name), InOrg: true, OrgID: orgID,
				Status: string(a.Status),
			})
		}
	}
}

// collectRoles is the main pass: every role, its trust policy, and - for the
// roles that turn out to be doors - what those doors grant.
func (c *Collector) collectRoles(ctx context.Context, res *model.Result, accountID string, providers map[string]*model.IdentityProvider) []model.Door {
	var roles []iamtypes.Role
	pager := iam.NewListRolesPaginator(c.iam, &iam.ListRolesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			c.note(res, accountID, "iam:ListRoles", "", err)
			break
		}
		roles = append(roles, page.Roles...)
	}

	type job struct {
		role       iamtypes.Role
		doors      []model.Door
		principal  model.Principal
		wantDetail bool
	}
	byARN := map[string]*job{}
	var jobs []*job

	// Pass one: parse every trust policy. Doors and same-account assume edges
	// both fall out of it, and the edges decide which extra roles need their
	// permissions read.
	for _, r := range roles {
		doc := aws.ToString(r.AssumeRolePolicyDocument)
		if doc == "" {
			continue
		}
		arn := aws.ToString(r.Arn)
		in := trustInput{
			AccountID:      accountID,
			RoleARN:        arn,
			RoleName:       aws.ToString(r.RoleName),
			RolePath:       aws.ToString(r.Path),
			Description:    aws.ToString(r.Description),
			Document:       doc,
			CreatedAt:      r.CreateDate,
			MaxSession:     aws.ToInt32(r.MaxSessionDuration),
			Providers:      providers,
			IncludeService: c.opts.IncludeService,
		}
		doors, edges, err := doorsFromTrustPolicy(in)
		if err != nil {
			c.note(res, accountID, "parse:AssumeRolePolicyDocument", arn, err)
			continue
		}

		j := &job{
			role:  r,
			doors: doors,
			principal: model.Principal{
				Provider: model.ProviderAWS, NodeID: arn,
				Name: aws.ToString(r.RoleName), AccountID: accountID,
			},
			wantDetail: len(doors) > 0,
		}
		byARN[arn] = j
		jobs = append(jobs, j)
		c.edges = append(c.edges, edges...)
	}

	// A role that is the source or target of an assume edge needs its
	// permissions read too, even with no door of its own: it may be the
	// privileged end of a chain, and that is the whole point of following one.
	for _, e := range c.edges {
		for _, arn := range []string{e.From, e.To} {
			if j, ok := byARN[arn]; ok {
				j.wantDetail = true
			}
		}
	}

	sem := make(chan struct{}, c.opts.concurrency())
	var wg sync.WaitGroup
	for _, j := range jobs {
		if !j.wantDetail {
			continue
		}
		wg.Add(1)
		go func(j *job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.enrich(ctx, res, accountID, j.role, j.doors, &j.principal)
		}(j)
	}
	wg.Wait()

	for _, j := range jobs {
		if j.wantDetail {
			res.Principals = append(res.Principals, j.principal)
		}
	}

	var out []model.Door
	for _, j := range jobs {
		out = append(out, j.doors...)
	}
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].ResourceARN != out[k].ResourceARN {
			return out[i].ResourceARN < out[k].ResourceARN
		}
		return out[i].StatementSID < out[k].StatementSID
	})
	return out
}

// enrich fills last-used and granted-actions on every door of one role, and
// on the principal entry that represents the role in the trust graph. The
// principal is filled even when the role has no doors: it may be the far end
// of a chain, and that is the end worth knowing about.
func (c *Collector) enrich(ctx context.Context, res *model.Result, accountID string, role iamtypes.Role, doors []model.Door, principal *model.Principal) {
	arn := aws.ToString(role.Arn)
	name := aws.ToString(role.RoleName)

	var lastUsed *time.Time
	var lastRegion string
	tags := map[string]string{}

	// ListRoles omits RoleLastUsed and tags; GetRole is the only source.
	if out, err := c.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName}); err != nil {
		c.note(res, accountID, "iam:GetRole", arn, err)
	} else if out.Role != nil {
		if out.Role.RoleLastUsed != nil {
			lastUsed = out.Role.RoleLastUsed.LastUsedDate
			lastRegion = aws.ToString(out.Role.RoleLastUsed.Region)
		}
		for _, t := range out.Role.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}

	grants, sources, partial := c.readRolePolicies(ctx, res, accountID, name, arn)

	for i := range doors {
		doors[i].LastUsed = lastUsed
		doors[i].LastUsedRegion = lastRegion
		if len(tags) > 0 {
			doors[i].Tags = tags
		}
		doors[i].GrantedActions = grants.Actions
		doors[i].IsPrivileged = grants.Privileged
		doors[i].PrivilegeReasons = grants.Reasons
		doors[i].Policies = sources
		doors[i].PoliciesPartial = partial
	}

	if principal != nil {
		principal.Grants = grants.Actions
		principal.Privileged = grants.Privileged
		principal.Reasons = grants.Reasons
	}
}

// readRolePolicies flattens attached managed policies and inline policies into
// one grant summary.
func (c *Collector) readRolePolicies(ctx context.Context, res *model.Result, accountID, roleName, roleARN string) (grantSummary, []model.PolicySource, bool) {
	var grants grantSummary
	var sources []model.PolicySource
	partial := false

	attachedPager := iam.NewListAttachedRolePoliciesPaginator(c.iam, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for attachedPager.HasMorePages() {
		page, err := attachedPager.NextPage(ctx)
		if err != nil {
			c.note(res, accountID, "iam:ListAttachedRolePolicies", roleARN, err)
			partial = true
			break
		}
		for _, ap := range page.AttachedPolicies {
			policyARN := aws.ToString(ap.PolicyArn)
			src := model.PolicySource{Type: "managed", Name: aws.ToString(ap.PolicyName), ARN: policyARN}

			// An AWS-managed admin policy is conclusive on its own, so the
			// door is still flagged even if the document read is denied.
			grants.flagManagedPolicy(policyARN)

			doc, err := c.managedPolicyDocument(ctx, policyARN)
			if err != nil {
				c.note(res, accountID, "iam:GetPolicyVersion", policyARN, err)
				src.Unread, src.Message = true, shortError(err)
				partial = true
				sources = append(sources, src)
				continue
			}
			grants.analyzeGrants(doc)
			sources = append(sources, src)
		}
	}

	inlinePager := iam.NewListRolePoliciesPaginator(c.iam, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for inlinePager.HasMorePages() {
		page, err := inlinePager.NextPage(ctx)
		if err != nil {
			c.note(res, accountID, "iam:ListRolePolicies", roleARN, err)
			partial = true
			break
		}
		for _, policyName := range page.PolicyNames {
			src := model.PolicySource{Type: "inline", Name: policyName}
			out, err := c.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName: aws.String(roleName), PolicyName: aws.String(policyName),
			})
			if err != nil {
				c.note(res, accountID, "iam:GetRolePolicy", roleARN+"/"+policyName, err)
				src.Unread, src.Message = true, shortError(err)
				partial = true
				sources = append(sources, src)
				continue
			}
			doc, err := parsePolicyDocument(aws.ToString(out.PolicyDocument))
			if err != nil {
				c.note(res, accountID, "parse:InlinePolicy", roleARN+"/"+policyName, err)
				src.Unread, src.Message = true, shortError(err)
				partial = true
				sources = append(sources, src)
				continue
			}
			grants.analyzeGrants(doc)
			sources = append(sources, src)
		}
	}

	grants.sort()
	return grants, sources, partial
}

func (c *Collector) managedPolicyDocument(ctx context.Context, policyARN string) (*policyDocument, error) {
	meta, err := c.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return nil, err
	}
	if meta.Policy == nil || meta.Policy.DefaultVersionId == nil {
		return nil, fmt.Errorf("policy %s has no default version", policyARN)
	}
	ver, err := c.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN), VersionId: meta.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}
	if ver.PolicyVersion == nil {
		return nil, fmt.Errorf("policy %s returned no version document", policyARN)
	}
	return parsePolicyDocument(aws.ToString(ver.PolicyVersion.Document))
}

// collectAccessKeys records long-lived IAM user keys. An account that has
// adopted federation but still has active static keys has two front doors,
// and only one of them is being watched.
func (c *Collector) collectAccessKeys(ctx context.Context, res *model.Result, accountID string) {
	pager := iam.NewListUsersPaginator(c.iam, &iam.ListUsersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			c.note(res, accountID, "iam:ListUsers", "", err)
			return
		}
		for _, u := range page.Users {
			userName := aws.ToString(u.UserName)
			out, err := c.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
			if err != nil {
				c.note(res, accountID, "iam:ListAccessKeys", aws.ToString(u.Arn), err)
				continue
			}
			for _, k := range out.AccessKeyMetadata {
				keyID := aws.ToString(k.AccessKeyId)
				key := model.AccessKey{
					AccountID:   accountID,
					UserName:    userName,
					UserARN:     aws.ToString(u.Arn),
					AccessKeyID: keyID, // an identifier, not a secret; the secret is never retrievable
					Status:      string(k.Status),
					CreatedAt:   k.CreateDate,
				}
				if lu, err := c.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
					AccessKeyId: k.AccessKeyId,
				}); err != nil {
					c.note(res, accountID, "iam:GetAccessKeyLastUsed", keyID, err)
				} else if lu.AccessKeyLastUsed != nil {
					key.LastUsed = lu.AccessKeyLastUsed.LastUsedDate
					key.LastService = aws.ToString(lu.AccessKeyLastUsed.ServiceName)
					key.LastRegion = aws.ToString(lu.AccessKeyLastUsed.Region)
				}
				res.AccessKeys = append(res.AccessKeys, key)
			}
		}
	}
}

// --- error handling ----------------------------------------------------------

var deniedCodes = map[string]bool{
	"AccessDenied":          true,
	"AccessDeniedException": true,
	"UnauthorizedOperation": true,
	"AuthorizationError":    true,
	"NotAuthorized":         true,
	"InvalidClientTokenId":  true,
}

// note records one thing the scan could not read. It is concurrency-safe
// because per-role enrichment runs in parallel.
func (c *Collector) note(res *model.Result, accountID, operation, resource string, err error) {
	code := ""
	msg := err.Error()
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
		msg = apiErr.ErrorMessage()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	res.AddUnreadable(model.Unreadable{
		Provider:  model.ProviderAWS,
		AccountID: accountID,
		Operation: operation,
		Resource:  resource,
		Code:      code,
		Message:   msg,
		Denied:    deniedCodes[code],
	})
}

func shortError(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	s := err.Error()
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func dedupe(in []string) []string {
	out := in[:0:0]
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}
