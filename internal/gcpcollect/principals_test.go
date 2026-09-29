package gcpcollect

import (
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

const (
	poolPath = "projects/123456789/locations/global/workloadIdentityPools/github"
	ghIssuer = "https://token.actions.githubusercontent.com"
)

func TestParseMember(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		kind       MemberKind
		poolName   string
		attribute  string
		value      string
		entirePool bool
		email      string
		project    string
		domain     string
	}{
		{
			name: "whole pool", raw: "principalSet://iam.googleapis.com/" + poolPath + "/*",
			kind: MemberFederated, poolName: "github", entirePool: true,
		},
		{
			name: "pool with no selector", raw: "principalSet://iam.googleapis.com/" + poolPath,
			kind: MemberFederated, poolName: "github", entirePool: true,
		},
		{
			name: "exact subject", raw: "principal://iam.googleapis.com/" + poolPath + "/subject/repo:acme/api:ref:refs/heads/main",
			kind: MemberFederated, poolName: "github",
			attribute: "subject", value: "repo:acme/api:ref:refs/heads/main",
		},
		{
			name: "mapped attribute", raw: "principalSet://iam.googleapis.com/" + poolPath + "/attribute.repository/acme/api",
			kind: MemberFederated, poolName: "github",
			attribute: "repository", value: "acme/api",
		},
		{
			name: "owner attribute", raw: "principalSet://iam.googleapis.com/" + poolPath + "/attribute.repository_owner/acme",
			kind: MemberFederated, poolName: "github",
			attribute: "repository_owner", value: "acme",
		},
		{
			name: "group", raw: "principalSet://iam.googleapis.com/" + poolPath + "/group/platform",
			kind: MemberFederated, poolName: "github", attribute: "group", value: "platform",
		},
		{
			name: "service account", raw: "serviceAccount:deploy@acme-prod.iam.gserviceaccount.com",
			kind: MemberServiceAccount, email: "deploy@acme-prod.iam.gserviceaccount.com", project: "acme-prod",
		},
		{
			name: "default compute service account has no parseable project",
			raw:  "serviceAccount:123456789-compute@developer.gserviceaccount.com",
			kind: MemberServiceAccount, email: "123456789-compute@developer.gserviceaccount.com", project: "",
		},
		{
			name: "user", raw: "user:alice@acme.com",
			kind: MemberUser, email: "alice@acme.com", domain: "acme.com",
		},
		{
			name: "group member", raw: "group:platform@acme.com",
			kind: MemberGroup, email: "platform@acme.com", domain: "acme.com",
		},
		{
			name: "domain", raw: "domain:acme.com", kind: MemberDomain, domain: "acme.com",
		},
		{
			name: "allUsers", raw: "allUsers", kind: MemberAllUsers,
		},
		{
			name: "allAuthenticatedUsers", raw: "allAuthenticatedUsers", kind: MemberAllUsers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ParseMember(tt.raw)

			if m.Kind != tt.kind {
				t.Errorf("Kind = %v, want %v", m.Kind, tt.kind)
			}
			if tt.poolName != "" && m.PoolName != tt.poolName {
				t.Errorf("PoolName = %q, want %q", m.PoolName, tt.poolName)
			}
			if m.EntirePool != tt.entirePool {
				t.Errorf("EntirePool = %v, want %v", m.EntirePool, tt.entirePool)
			}
			if tt.attribute != "" && m.Attribute != tt.attribute {
				t.Errorf("Attribute = %q, want %q", m.Attribute, tt.attribute)
			}
			if tt.value != "" && m.Value != tt.value {
				t.Errorf("Value = %q, want %q", m.Value, tt.value)
			}
			if tt.email != "" && m.Email != tt.email {
				t.Errorf("Email = %q, want %q", m.Email, tt.email)
			}
			if m.Project != tt.project {
				t.Errorf("Project = %q, want %q", m.Project, tt.project)
			}
			if tt.domain != "" && m.Domain != tt.domain {
				t.Errorf("Domain = %q, want %q", m.Domain, tt.domain)
			}
			if m.Raw != tt.raw {
				t.Errorf("Raw = %q, want the input preserved", m.Raw)
			}
		})
	}
}

// The pool path itself must survive parsing, because the fix text has to name
// the exact member string to remove.
func TestParseMemberKeepsPoolPath(t *testing.T) {
	m := ParseMember("principalSet://iam.googleapis.com/" + poolPath + "/*")
	if m.Pool != poolPath {
		t.Errorf("Pool = %q, want %q", m.Pool, poolPath)
	}
}

func TestPartyFor(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		issuer  string
		kind    model.PartyKind
		scope   model.Scope
		display string
		org     string
		project string
	}{
		{
			name: "whole pool is anyone", raw: "principalSet://iam.googleapis.com/" + poolPath + "/*",
			issuer: ghIssuer, kind: model.PartyGitHub, scope: model.ScopeAnyone,
			display: "ANY GitHub Actions tenant (whole pool github)",
		},
		{
			name:   "exact subject reuses the github grammar",
			raw:    "principal://iam.googleapis.com/" + poolPath + "/subject/repo:acme/api:ref:refs/heads/main",
			issuer: ghIssuer, kind: model.PartyGitHub, scope: model.ScopeExact,
			display: "github.com/acme/api @ refs/heads/main", org: "acme", project: "api",
		},
		{
			name:   "repository attribute pins the repo but not the ref",
			raw:    "principalSet://iam.googleapis.com/" + poolPath + "/attribute.repository/acme/api",
			issuer: ghIssuer, kind: model.PartyGitHub, scope: model.ScopeProject,
			org: "acme", project: "acme/api",
		},
		{
			name:   "repository_owner is org wide",
			raw:    "principalSet://iam.googleapis.com/" + poolPath + "/attribute.repository_owner/acme",
			issuer: ghIssuer, kind: model.PartyGitHub, scope: model.ScopeOrg, org: "acme",
		},
		{
			name: "domain admits everyone in it", raw: "domain:acme.com",
			kind: model.PartyGoogleDomain, scope: model.ScopeDomain, org: "acme.com",
		},
		{
			name: "allUsers", raw: "allUsers",
			kind: model.PartyAnyone, scope: model.ScopeAnyone,
			display: "ANYONE, authenticated or not (allUsers)",
		},
		{
			name: "cross-project service account", raw: "serviceAccount:ci@other-project.iam.gserviceaccount.com",
			kind: model.PartyGCPServiceAcct, scope: model.ScopeExact,
			display: "GCP service account ci@other-project.iam.gserviceaccount.com",
			org:     "other-project", project: "other-project",
		},
		{
			name:   "unrecognised attribute is not guessed at",
			raw:    "principalSet://iam.googleapis.com/" + poolPath + "/attribute.custom_thing/whatever",
			issuer: ghIssuer, kind: model.PartyGitHub, scope: model.ScopeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PartyFor(ParseMember(tt.raw), providerWithIssuer(tt.issuer))

			if p.Kind != tt.kind {
				t.Errorf("Kind = %q, want %q", p.Kind, tt.kind)
			}
			if p.Scope != tt.scope {
				t.Errorf("Scope = %q, want %q", p.Scope, tt.scope)
			}
			if tt.display != "" && p.Display != tt.display {
				t.Errorf("Display = %q, want %q", p.Display, tt.display)
			}
			if tt.org != "" && p.Org != tt.org {
				t.Errorf("Org = %q, want %q", p.Org, tt.org)
			}
			if tt.project != "" && p.Project != tt.project {
				t.Errorf("Project = %q, want %q", p.Project, tt.project)
			}
			if p.Display == "" {
				t.Error("Display is empty; every party must be describable in one line")
			}
		})
	}
}

// Without a provider we do not know the issuer, so the party must not claim a
// platform it cannot verify.
func TestPartyForUnknownIssuer(t *testing.T) {
	p := PartyFor(ParseMember("principalSet://iam.googleapis.com/"+poolPath+"/*"), nil)
	if p.Kind != model.PartyWIFPool {
		t.Errorf("Kind = %q, want workload_identity_pool", p.Kind)
	}
	if p.Scope != model.ScopeAnyone {
		t.Errorf("Scope = %q, want anyone", p.Scope)
	}
}

func TestIsExternalMember(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"principalSet://iam.googleapis.com/" + poolPath + "/*", true},
		{"allUsers", true},
		{"domain:acme.com", true},
		{"user:alice@acme.com", true},
		{"serviceAccount:ci@other-project.iam.gserviceaccount.com", true},
		{"serviceAccount:ci@acme-prod.iam.gserviceaccount.com", false}, // our own project
		{"serviceAccount:123-compute@developer.gserviceaccount.com", false},
	}
	for _, c := range cases {
		if got := isExternalMember(ParseMember(c.raw), "acme-prod"); got != c.want {
			t.Errorf("isExternalMember(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// providerWithIssuer builds the minimum provider a party parse needs: the
// issuer decides which subject grammar applies.
func providerWithIssuer(issuer string) *model.IdentityProvider {
	if issuer == "" {
		return nil
	}
	return &model.IdentityProvider{
		Provider: model.ProviderGCP, ARN: poolPath + "/providers/gh",
		Pool: poolPath, Type: model.PrincipalOIDC, URL: issuer,
	}
}
