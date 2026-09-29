// Package azcollect reads federated trust out of an Entra ID tenant and the
// Azure subscriptions under it.
//
// READ-ONLY. Every call that reads your tenant or your subscriptions is a GET.
// The only POST in this package is the OAuth token request to
// login.microsoftonline.com, which is how you authenticate - it creates nothing
// and changes nothing. There is no code path that mutates a resource.
// A denied call is recorded in Result.Unreadable and the scan continues.
//
// BETA. The mapping from Azure's model onto the shared Door struct is newer
// than the AWS and GCP ones, and Azure has more shapes of federation than
// either - app registrations, user-assigned managed identities, multi-tenant
// apps and guest accounts all admit someone from outside. Findings from this
// collector are worth reading; they are not yet worth failing a build on
// without looking.
package azcollect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/secorvia/frontdoor/internal/issuers"
	"github.com/secorvia/frontdoor/internal/model"
)

const (
	graphBase = "https://graph.microsoft.com/v1.0"
	armBase   = "https://management.azure.com"

	// The audience Entra ID requires on a federated credential. Anything else
	// is a token minted for somebody other than Azure.
	expectedAudience = "api://AzureADTokenExchange"
)

// Options configure an Azure scan.
type Options struct {
	TenantID      string
	Subscriptions []string
	SkipARM       bool // skip role assignments and managed identities
	SkipGuests    bool
	Concurrency   int
}

func (o Options) concurrency() int {
	if o.Concurrency > 0 {
		return o.Concurrency
	}
	return 6
}

// Collector holds the HTTP client and token source for one tenant.
type Collector struct {
	opts   Options
	client *http.Client
	tokens *tokenSource

	mu    sync.Mutex
	edges []model.Hop
}

// New builds a Collector. Credentials come from the environment, the instance
// metadata service, or the Azure CLI - see auth.go. frontdoor never reads a
// credential file of its own and never writes one.
func New(ctx context.Context, opts Options) (*Collector, error) {
	tenant := opts.TenantID
	if tenant == "" {
		tenant = firstNonEmpty(os.Getenv("AZURE_TENANT_ID"), os.Getenv("ARM_TENANT_ID"))
	}

	client := &http.Client{Timeout: 60 * time.Second}
	c := &Collector{opts: opts, client: client, tokens: newTokenSource(client, tenant)}

	// Fail here rather than three calls in, so the error names the credential
	// problem instead of an HTTP status.
	if _, err := c.tokens.Token(ctx, graphScope); err != nil {
		return nil, err
	}
	return c, nil
}

// ImpersonationEdges returns the links this collector found. Azure's are
// role assignments that let one identity act as another.
func (c *Collector) ImpersonationEdges() []model.Hop {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.Hop(nil), c.edges...)
}

// Collect runs the whole Azure pass and appends to res.
func (c *Collector) Collect(ctx context.Context, res *model.Result) error {
	tenant := c.tokens.tenantID
	res.Accounts = append(res.Accounts, model.Account{
		Provider: model.ProviderAzure, ID: orUnknown(tenant), Name: "Entra ID tenant", Scanned: true,
	})

	// Service principals first: role assignments reference them by object id,
	// and an app registration means nothing without the principal it backs.
	principals := c.collectServicePrincipals(ctx, res, tenant)
	c.collectApplications(ctx, res, tenant, principals)

	if !c.opts.SkipGuests {
		c.collectGuests(ctx, res, tenant)
	}
	if !c.opts.SkipARM {
		c.collectARM(ctx, res, tenant, principals)
	}
	return nil
}

// spIndex maps appId and objectId to the service principal, which is the join
// between "what has a door" and "what holds permissions".
type spIndex struct {
	byAppID  map[string]*servicePrincipal
	byObject map[string]*servicePrincipal
	roles    map[string][]string // object id -> role names
}

func (c *Collector) collectServicePrincipals(ctx context.Context, res *model.Result, tenant string) *spIndex {
	idx := &spIndex{
		byAppID:  map[string]*servicePrincipal{},
		byObject: map[string]*servicePrincipal{},
		roles:    map[string][]string{},
	}

	sps, err := graphList[servicePrincipal](ctx, c, graphBase+
		"/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled&$top=999")
	if err != nil {
		c.note(res, tenant, "graph:servicePrincipals.list", "", err)
		return idx
	}
	for i := range sps {
		sp := &sps[i]
		idx.byAppID[sp.AppID] = sp
		idx.byObject[sp.ID] = sp
	}
	return idx
}

// collectApplications reads app registrations and turns every federated
// identity credential into a door.
func (c *Collector) collectApplications(ctx context.Context, res *model.Result, tenant string, idx *spIndex) {
	apps, err := graphList[application](ctx, c, graphBase+
		"/applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials&$top=999")
	if err != nil {
		c.note(res, tenant, "graph:applications.list", "", err)
		return
	}

	sem := make(chan struct{}, c.opts.concurrency())
	var wg sync.WaitGroup
	type result struct {
		doors []model.Door
		keys  []model.AccessKey
		prin  *model.Principal
	}
	results := make([]result, len(apps))

	for i := range apps {
		wg.Add(1)
		go func(i int, app application) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.oneApplication(ctx, res, tenant, app, idx)
		}(i, apps[i])
	}
	wg.Wait()

	for _, r := range results {
		res.Doors = append(res.Doors, r.doors...)
		res.AccessKeys = append(res.AccessKeys, r.keys...)
		if r.prin != nil {
			res.Principals = append(res.Principals, *r.prin)
		}
	}
}

func (c *Collector) oneApplication(ctx context.Context, res *model.Result, tenant string, app application, idx *spIndex) (out struct {
	doors []model.Door
	keys  []model.AccessKey
	prin  *model.Principal
}) {
	sp := idx.byAppID[app.AppID]
	node := app.AppID
	if sp != nil {
		// Role assignments name the service principal's object id, so that is
		// what the graph has to address this identity by.
		node = sp.ID
	}

	roles := idx.roles[node]
	privileged, reasons := classifyRoles(roles)

	out.prin = &model.Principal{
		Provider: model.ProviderAzure, NodeID: node,
		Name: app.DisplayName, AccountID: tenant,
		Grants: roles, Privileged: privileged, Reasons: reasons,
	}

	// A multi-tenant app is a door in its own right: any tenant can consent to
	// it and obtain a principal in their own directory that maps to this app.
	if who, multi := multiTenantAudience(app.SignInAudience); multi {
		out.doors = append(out.doors, model.Door{
			Provider: model.ProviderAzure, AccountID: tenant,
			ResourceARN: "/applications/" + app.ID, ResourceName: app.DisplayName, NodeID: node,
			PrincipalType:  model.PrincipalCrossAccount,
			TrustActions:   []string{"signInAudience=" + app.SignInAudience},
			GrantedActions: roles, IsPrivileged: privileged, PrivilegeReasons: reasons,
			ExternalParties: []model.ExternalParty{{
				Kind: model.PartyEntraTenant, Scope: model.ScopeAnyone, Wildcard: true,
				Display: "ANY identity from " + who, Subject: app.SignInAudience,
			}},
			Conditions: []model.Condition{
				{Operator: "equals", Key: "signInAudience", Values: []string{app.SignInAudience}},
			},
		})
	}

	fics, err := graphList[federatedIdentityCredential](ctx, c,
		graphBase+"/applications/"+url.PathEscape(app.ID)+"/federatedIdentityCredentials")
	if err != nil {
		c.note(res, tenant, "graph:federatedIdentityCredentials.list", app.DisplayName, err)
	}
	for _, fic := range fics {
		out.doors = append(out.doors, c.ficDoor(tenant, node, "/applications/"+app.ID, app.DisplayName, fic, roles, privileged, reasons))
	}

	// Secrets and certificates alongside federation: the same mistake FD020
	// catches on AWS and GCP, in Azure's vocabulary.
	if len(fics) > 0 || len(out.doors) > 0 {
		out.keys = append(out.keys, credentialKeys(tenant, app)...)
	}
	return out
}

// ficDoor turns one federated identity credential into a Door. Azure's
// issuer+subject pair maps onto the shared model almost exactly, which is why
// the subject parsers are shared rather than reimplemented here.
func (c *Collector) ficDoor(tenant, node, resourceID, displayName string,
	fic federatedIdentityCredential, roles []string, privileged bool, reasons []string) model.Door {

	conds := []model.Condition{
		{Operator: "equals", Key: "iss", Values: []string{fic.Issuer}},
	}
	if len(fic.Audiences) > 0 {
		conds = append(conds, model.Condition{Operator: "equals", Key: "aud", Values: fic.Audiences})
	}

	var party model.ExternalParty
	switch {
	case fic.ClaimsMatchingExpression != nil && fic.ClaimsMatchingExpression.Value != "":
		// The flexible form can match a whole set of subjects at once, which
		// is the Azure way of writing repo:acme/*.
		conds = append(conds, model.Condition{
			Operator: "matches", Key: "claimsMatchingExpression",
			Values: []string{fic.ClaimsMatchingExpression.Value},
		})
		party = expressionParty(fic.Issuer, fic.ClaimsMatchingExpression.Value)
	case fic.Subject == "":
		party = model.ExternalParty{
			Kind: issuers.KindFor(fic.Issuer), Scope: model.ScopeAnyone, Wildcard: true,
			Display: "ANY identity " + issuers.DisplayName(fic.Issuer) + " will issue a token for",
		}
	default:
		conds = append(conds, model.Condition{Operator: "equals", Key: "sub", Values: []string{fic.Subject}})
		party = issuers.ParseSubject(fic.Issuer, fic.Subject)
	}

	return model.Door{
		Provider: model.ProviderAzure, AccountID: tenant,
		ResourceARN: resourceID, ResourceName: displayName, NodeID: node,
		PrincipalType:    model.PrincipalOIDC,
		Issuer:           fic.Issuer,
		Audiences:        fic.Audiences,
		Conditions:       conds,
		ExternalParties:  []model.ExternalParty{party},
		TrustActions:     []string{"federatedIdentityCredential:" + fic.Name},
		GrantedActions:   roles,
		IsPrivileged:     privileged,
		PrivilegeReasons: reasons,
		Description:      fic.Description,
	}
}

// expressionParty reads what it can out of a claims-matching expression.
// Azure's grammar here is narrow - claims['sub'] matches 'pattern' - but the
// pattern is the whole question, so an unrecognised expression is reported as
// unknown rather than guessed at.
func expressionParty(issuer, expression string) model.ExternalParty {
	pattern := extractMatchPattern(expression)
	if pattern == "" {
		return model.ExternalParty{
			Kind:    issuers.KindFor(issuer),
			Scope:   model.ScopeUnknown,
			Display: "identities matching an expression frontdoor could not read",
			Subject: expression,
		}
	}

	p := issuers.ParseSubject(issuer, pattern)
	p.Subject = expression
	p.Wildcard = strings.ContainsAny(pattern, "*?")
	return p
}

// extractMatchPattern pulls the quoted pattern out of a claims expression.
func extractMatchPattern(expression string) string {
	lower := strings.ToLower(expression)
	if !strings.Contains(lower, "matches") && !strings.Contains(lower, "eq ") {
		return ""
	}
	// The pattern is the last single-quoted literal.
	last := strings.LastIndex(expression, "'")
	if last <= 0 {
		return ""
	}
	first := strings.LastIndex(expression[:last], "'")
	if first < 0 {
		return ""
	}
	return expression[first+1 : last]
}

func credentialKeys(tenant string, app application) []model.AccessKey {
	var out []model.AccessKey
	add := func(kind string, creds []credential) {
		for _, cr := range creds {
			k := model.AccessKey{
				Provider: model.ProviderAzure, AccountID: tenant,
				UserName: app.DisplayName, UserARN: "/applications/" + app.ID,
				AccessKeyID: kind + " " + orUnknown(cr.KeyID), Status: "Active",
			}
			if t, err := time.Parse(time.RFC3339, cr.StartDate); err == nil {
				k.CreatedAt = &t
			}
			// Entra ID does not report last-use for app credentials, and the
			// rules must not read that silence as "never used".
			out = append(out, k)
		}
	}
	add("client secret", app.PasswordCreds)
	add("certificate", app.KeyCreds)
	return out
}

// collectGuests records accounts from other tenants that hold access in this
// one. They are not federation, but they are a way in that nobody inventories.
func (c *Collector) collectGuests(ctx context.Context, res *model.Result, tenant string) {
	guests, err := graphList[guestUser](ctx, c, graphBase+
		"/users?$filter=userType%20eq%20'Guest'&$select=id,displayName,userPrincipalName,mail,externalUserState&$top=999")
	if err != nil {
		c.note(res, tenant, "graph:users.list(guests)", "", err)
		return
	}

	for _, g := range guests {
		home := guestHomeDomain(g)
		res.Doors = append(res.Doors, model.Door{
			Provider: model.ProviderAzure, AccountID: tenant,
			ResourceARN: "/users/" + g.ID, ResourceName: orUnknown(g.DisplayName), NodeID: g.ID,
			PrincipalType: model.PrincipalCrossAccount,
			TrustActions:  []string{"guest:" + orUnknown(g.ExternalUserState)},
			ExternalParties: []model.ExternalParty{{
				Kind: model.PartyEntraGuest, Scope: model.ScopeExact,
				Display: "guest " + orUnknown(g.UserPrincipalName) + " from " + home,
				Org:     home, Subject: g.UserPrincipalName,
			}},
		})
	}
}

// guestHomeDomain reads the original tenant out of the mangled guest UPN,
// which Entra ID writes as user_example.com#EXT#@yourtenant.onmicrosoft.com.
func guestHomeDomain(g guestUser) string {
	upn := g.UserPrincipalName
	if i := strings.Index(upn, "#EXT#"); i > 0 {
		original := upn[:i]
		if j := strings.LastIndex(original, "_"); j > 0 {
			return original[j+1:]
		}
	}
	if _, host, ok := strings.Cut(g.Mail, "@"); ok {
		return host
	}
	return "another tenant"
}

// --- ARM ---------------------------------------------------------------------

// collectARM reads subscriptions, role assignments and user-assigned managed
// identities. Role assignments are what make a door matter; managed identity
// federated credentials are doors in their own right.
func (c *Collector) collectARM(ctx context.Context, res *model.Result, tenant string, idx *spIndex) {
	subs, err := c.subscriptions(ctx)
	if err != nil {
		c.note(res, tenant, "arm:subscriptions.list", "", err)
		return
	}

	roleNames := map[string]string{}
	for _, sub := range subs {
		c.collectRoleAssignments(ctx, res, tenant, sub, idx, roleNames)
		c.collectManagedIdentities(ctx, res, tenant, sub, idx)
	}
}

func (c *Collector) subscriptions(ctx context.Context) ([]subscription, error) {
	all, err := armList[subscription](ctx, c, armBase+"/subscriptions?api-version=2022-12-01")
	if err != nil {
		return nil, err
	}

	var active []subscription
	for _, s := range all {
		if s.State != "Enabled" {
			continue
		}
		if len(c.opts.Subscriptions) > 0 && !contains(c.opts.Subscriptions, s.SubscriptionID) {
			continue
		}
		active = append(active, s)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].SubscriptionID < active[j].SubscriptionID })
	return active, nil
}

func (c *Collector) collectRoleAssignments(ctx context.Context, res *model.Result, tenant string,
	sub subscription, idx *spIndex, roleNames map[string]string) {

	assignments, err := armList[roleAssignment](ctx, c, armBase+"/subscriptions/"+sub.SubscriptionID+
		"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
	if err != nil {
		c.note(res, tenant, "arm:roleAssignments.list", sub.SubscriptionID, err)
		return
	}

	for _, a := range assignments {
		name := c.roleName(ctx, res, tenant, a.Properties.RoleDefinitionID, roleNames)
		if name == "" {
			continue
		}
		idx.roles[a.Properties.PrincipalID] = appendUnique(idx.roles[a.Properties.PrincipalID], name)
	}
}

// roleName resolves a role definition id to its name, caching it. When the
// read is denied it falls back to the table of built-in ids, and an id in
// neither place returns empty rather than a guess.
func (c *Collector) roleName(ctx context.Context, res *model.Result, tenant, id string, cache map[string]string) string {
	if id == "" {
		return ""
	}
	c.mu.Lock()
	if name, ok := cache[id]; ok {
		c.mu.Unlock()
		return name
	}
	c.mu.Unlock()

	name := ""
	var def roleDefinition
	if err := c.getJSON(ctx, armScope, armBase+id+"?api-version=2022-04-01", &def); err != nil {
		c.note(res, tenant, "arm:roleDefinitions.get", id, err)
		name = roleNameFromID(id)
	} else {
		name = def.Properties.RoleName
	}

	c.mu.Lock()
	cache[id] = name
	c.mu.Unlock()
	return name
}

func (c *Collector) collectManagedIdentities(ctx context.Context, res *model.Result, tenant string,
	sub subscription, idx *spIndex) {

	identities, err := armList[userAssignedIdentity](ctx, c, armBase+"/subscriptions/"+sub.SubscriptionID+
		"/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31")
	if err != nil {
		c.note(res, tenant, "arm:userAssignedIdentities.list", sub.SubscriptionID, err)
		return
	}

	for _, mi := range identities {
		node := mi.Properties.PrincipalID
		roles := idx.roles[node]
		privileged, reasons := classifyRoles(roles)

		res.Principals = append(res.Principals, model.Principal{
			Provider: model.ProviderAzure, NodeID: node, Name: mi.Name, AccountID: tenant,
			Grants: roles, Privileged: privileged, Reasons: reasons,
		})

		creds, err := armList[armFederatedCredential](ctx, c, armBase+mi.ID+
			"/federatedIdentityCredentials?api-version=2023-01-31")
		if err != nil {
			c.note(res, tenant, "arm:managedIdentity.federatedIdentityCredentials.list", mi.Name, err)
			continue
		}
		for _, cr := range creds {
			res.Doors = append(res.Doors, c.ficDoor(tenant, node, mi.ID, mi.Name,
				federatedIdentityCredential{
					Name:      cr.Name,
					Issuer:    cr.Properties.Issuer,
					Subject:   cr.Properties.Subject,
					Audiences: cr.Properties.Audiences,
				}, roles, privileged, reasons))
		}
	}
}

// --- HTTP --------------------------------------------------------------------

// graphList walks a Graph collection through its @odata.nextLink pages.
func graphList[T any](ctx context.Context, c *Collector, url string) ([]T, error) {
	var out []T
	for url != "" {
		var page graphPage[T]
		if err := c.getJSON(ctx, graphScope, url, &page); err != nil {
			return out, err
		}
		out = append(out, page.Value...)
		url = page.NextLink
		if len(out) > 20000 {
			break // a tenant this size needs a filter, not a longer loop
		}
	}
	return out, nil
}

// armList walks an ARM collection through its nextLink pages.
func armList[T any](ctx context.Context, c *Collector, url string) ([]T, error) {
	var out []T
	for url != "" {
		var page armPage[T]
		if err := c.getJSON(ctx, armScope, url, &page); err != nil {
			return out, err
		}
		out = append(out, page.Value...)
		url = page.NextLink
		if len(out) > 20000 {
			break
		}
	}
	return out, nil
}

// apiError carries the status so note can tell a denial from a failure.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("%d: %s", e.Status, e.Message)
}

func (c *Collector) getJSON(ctx context.Context, scope, endpoint string, out any) error {
	token, err := c.tokens.Token(ctx, scope)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &apiError{Status: resp.StatusCode, Code: errorCode(body), Message: firstLine(errorMessage(body))}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// errorCode and errorMessage read both the Graph and ARM error envelopes,
// which differ only in nesting.
func errorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func errorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return string(body)
}

// --- helpers -----------------------------------------------------------------

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

func (c *Collector) note(res *model.Result, tenant, operation, resource string, err error) {
	code, denied := "", false
	msg := err.Error()

	if ae, ok := err.(*apiError); ok {
		code = fmt.Sprintf("%d", ae.Status)
		if ae.Code != "" {
			code += " " + ae.Code
		}
		msg = ae.Message
		denied = ae.Status == http.StatusForbidden || ae.Status == http.StatusUnauthorized
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	res.AddUnreadable(model.Unreadable{
		Provider: model.ProviderAzure, AccountID: tenant,
		Operation: operation, Resource: resource,
		Code: code, Message: msg, Denied: denied,
	})
}

func appendUnique(list []string, s string) []string {
	if s == "" {
		return list
	}
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	return append(list, s)
}

func contains(list []string, s string) bool {
	for _, existing := range list {
		if strings.EqualFold(existing, s) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
