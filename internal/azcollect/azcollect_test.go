package azcollect

import (
	"strings"
	"testing"

	"github.com/secorvia/frontdoor/internal/issuers"
	"github.com/secorvia/frontdoor/internal/model"
)

const ghIssuer = "https://token.actions.githubusercontent.com"

// A federated identity credential is the closest thing in any cloud to an AWS
// trust policy, so the subject parsing is shared rather than reimplemented.
// These tests prove the shared grammar actually reaches it.
func TestFICDoorUsesTheSharedSubjectGrammar(t *testing.T) {
	c := &Collector{}
	d := c.ficDoor("tenant-1", "sp-object-id", "/applications/app-1", "ci-deploy",
		federatedIdentityCredential{
			Name: "github-main", Issuer: ghIssuer,
			Subject:   "repo:acme/api:ref:refs/heads/main",
			Audiences: []string{expectedAudience},
		}, nil, false, nil)

	if d.Provider != model.ProviderAzure {
		t.Errorf("Provider = %q, want azure", d.Provider)
	}
	if d.NodeID != "sp-object-id" {
		t.Errorf("NodeID = %q; role assignments name the service principal, so the graph must too", d.NodeID)
	}
	if len(d.ExternalParties) != 1 {
		t.Fatalf("want 1 party, got %d", len(d.ExternalParties))
	}

	p := d.ExternalParties[0]
	if p.Kind != model.PartyGitHub {
		t.Errorf("Kind = %q, want github_actions", p.Kind)
	}
	if p.Scope != model.ScopeExact {
		t.Errorf("Scope = %q, want exact", p.Scope)
	}
	if p.Display != "github.com/acme/api @ refs/heads/main" {
		t.Errorf("Display = %q", p.Display)
	}
}

// Entra ID lets a credential omit the subject when a claims expression is
// used. With neither, nothing pins the caller.
func TestFICDoorWithNoSubject(t *testing.T) {
	c := &Collector{}
	d := c.ficDoor("tenant-1", "sp", "/applications/app-1", "ci",
		federatedIdentityCredential{Name: "loose", Issuer: ghIssuer}, nil, false, nil)

	p := d.ExternalParties[0]
	if p.Scope != model.ScopeAnyone {
		t.Errorf("Scope = %q, want anyone", p.Scope)
	}
	if !p.Wildcard {
		t.Error("Wildcard = false on a credential with no subject")
	}
}

func TestExtractMatchPattern(t *testing.T) {
	cases := map[string]string{
		"claims['sub'] matches 'repo:acme/*:ref:refs/heads/*'":      "repo:acme/*:ref:refs/heads/*",
		`claims["sub"] matches 'repo:acme/api:ref:refs/heads/main'`: "repo:acme/api:ref:refs/heads/main",
		"claims['sub'] eq 'repo:acme/api:environment:prod'":         "repo:acme/api:environment:prod",
		"has(claims.enterprise) && claims.enterprise.size() > 0":    "",
		"": "",
	}
	for expression, want := range cases {
		if got := extractMatchPattern(expression); got != want {
			t.Errorf("extractMatchPattern(%q) = %q, want %q", expression, got, want)
		}
	}
}

// The flexible form is how Azure writes repo:acme/*, so it has to widen the
// scope the same way a wildcard subject does.
func TestExpressionPartyWidensScope(t *testing.T) {
	p := expressionParty(ghIssuer, "claims['sub'] matches 'repo:acme/*'")
	if p.Scope != model.ScopeOrg {
		t.Errorf("Scope = %q, want org for repo:acme/*", p.Scope)
	}
	if !p.Wildcard {
		t.Error("Wildcard = false on a wildcard expression")
	}
	if p.Org != "acme" {
		t.Errorf("Org = %q, want acme", p.Org)
	}
}

// An expression we cannot read must be reported as unknown, never guessed
// into "wide open" or "pinned".
func TestExpressionPartyAdmitsWhatItCannotRead(t *testing.T) {
	p := expressionParty(ghIssuer, "has(claims.enterprise) && claims.enterprise.size() > 0")
	if p.Scope != model.ScopeUnknown {
		t.Errorf("Scope = %q, want unknown", p.Scope)
	}
	if !strings.Contains(p.Display, "could not read") {
		t.Errorf("Display does not admit the gap: %q", p.Display)
	}
}

func TestMultiTenantAudience(t *testing.T) {
	open := []string{"AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount"}
	for _, a := range open {
		if _, ok := multiTenantAudience(a); !ok {
			t.Errorf("multiTenantAudience(%q) = false, want true", a)
		}
	}
	if _, ok := multiTenantAudience("AzureADMyOrg"); ok {
		t.Error("a single-tenant app was reported as multi-tenant")
	}
}

func TestClassifyRole(t *testing.T) {
	privileged := []string{
		"Owner", "Contributor", "User Access Administrator",
		"Global Administrator", "Key Vault Secrets Officer",
		"Virtual Machine Contributor", "Managed Identity Operator",
	}
	for _, r := range privileged {
		if _, ok := ClassifyRole(r); !ok {
			t.Errorf("ClassifyRole(%q) = not privileged, want privileged", r)
		}
	}

	benign := []string{"Reader", "Monitoring Reader", "Cost Management Reader"}
	for _, r := range benign {
		if why, ok := ClassifyRole(r); ok {
			t.Errorf("ClassifyRole(%q) = privileged (%s), want not privileged", r, why)
		}
	}
}

// The well-known GUID table is only a fallback for when roleDefinitions is
// denied. An id it does not know must return empty rather than a guess.
func TestRoleNameFromID(t *testing.T) {
	const owner = "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	if got := roleNameFromID(owner); got != "Owner" {
		t.Errorf("roleNameFromID(owner) = %q, want Owner", got)
	}
	if got := roleNameFromID("/x/roleDefinitions/00000000-0000-0000-0000-000000000000"); got != "" {
		t.Errorf("an unknown role id produced %q, want empty", got)
	}
}

// Entra ID mangles a guest's original address into the UPN. Reading the home
// domain back out is what makes the door say where the person came from.
func TestGuestHomeDomain(t *testing.T) {
	cases := []struct {
		guest guestUser
		want  string
	}{
		{guestUser{UserPrincipalName: "alice_partner.com#EXT#@acme.onmicrosoft.com"}, "partner.com"},
		{guestUser{UserPrincipalName: "bob#EXT#@acme.onmicrosoft.com", Mail: "bob@other.com"}, "other.com"},
		{guestUser{UserPrincipalName: "weird"}, "another tenant"},
	}
	for _, c := range cases {
		if got := guestHomeDomain(c.guest); got != c.want {
			t.Errorf("guestHomeDomain(%+v) = %q, want %q", c.guest, got, c.want)
		}
	}
}

// Kubernetes subjects arrive on Azure more often than anywhere else, because
// AKS workload identity is the default way to run in-cluster.
func TestKubernetesSubject(t *testing.T) {
	p := issuers.ParseSubject("https://oidc.prod-aks.azure.com/abc123/", "system:serviceaccount:payments:deployer")

	if p.Kind != model.PartyKubernetes {
		t.Errorf("Kind = %q, want kubernetes", p.Kind)
	}
	if p.Scope != model.ScopeExact {
		t.Errorf("Scope = %q, want exact", p.Scope)
	}
	if p.Org != "payments" || p.Project != "deployer" {
		t.Errorf("namespace/name = %q/%q, want payments/deployer", p.Org, p.Project)
	}
	if p.Display != "k8s payments/deployer" {
		t.Errorf("Display = %q", p.Display)
	}
}

// A wildcard on either half widens it, and the report has to say which half.
func TestKubernetesWildcards(t *testing.T) {
	anyAccount := issuers.ParseSubject("https://oidc.eks.eu-west-1.amazonaws.com/id/X",
		"system:serviceaccount:payments:*")
	if anyAccount.Scope != model.ScopeOrg {
		t.Errorf("Scope = %q, want org for a wildcard service account", anyAccount.Scope)
	}
	if !strings.Contains(anyAccount.Display, "payments") {
		t.Errorf("Display does not name the namespace: %q", anyAccount.Display)
	}

	anyNamespace := issuers.ParseSubject("https://oidc.eks.eu-west-1.amazonaws.com/id/X",
		"system:serviceaccount:*:deployer")
	if anyNamespace.Scope != model.ScopeOrg {
		t.Errorf("Scope = %q, want org for a wildcard namespace", anyNamespace.Scope)
	}
	if !strings.Contains(anyNamespace.Display, "ANY namespace") {
		t.Errorf("Display does not say the namespace is unconstrained: %q", anyNamespace.Display)
	}
}

func TestErrorEnvelopes(t *testing.T) {
	graph := []byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}`)
	if got := errorCode(graph); got != "Authorization_RequestDenied" {
		t.Errorf("errorCode(graph) = %q", got)
	}
	if got := errorMessage(graph); got != "Insufficient privileges." {
		t.Errorf("errorMessage(graph) = %q", got)
	}

	arm := []byte(`{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	if got := errorCode(arm); got != "AuthorizationFailed" {
		t.Errorf("errorCode(arm) = %q", got)
	}

	// A body that is not an error envelope at all must still produce something
	// a person can read rather than an empty string.
	if got := errorMessage([]byte("gateway timeout")); got != "gateway timeout" {
		t.Errorf("errorMessage(plain) = %q", got)
	}
}

// Error text can run to paragraphs and carry a correlation id. One line of it
// is useful; the rest is noise in a terminal report.
func TestFirstLine(t *testing.T) {
	long := "Insufficient privileges to complete the operation.\nCorrelation ID: abc\nTimestamp: now"
	if got := firstLine(long); got != "Insufficient privileges to complete the operation." {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine(strings.Repeat("x", 400)); len(got) > 210 {
		t.Errorf("firstLine did not cap a very long message: %d chars", len(got))
	}
}
