package issuers

import (
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

// AWS publishes the list of shared OIDC providers it applies identity-provider
// controls to. Recognising them by name is half the job; the other half is
// knowing which claim names the tenant, because for several of them it is not
// the subject, and reading an absent subject as "open" puts a critical on a
// correct configuration.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html
func TestSharedOIDCProviders(t *testing.T) {
	tests := []struct {
		issuer     string
		name       string
		tenancyKey string
	}{
		{"token.actions.githubusercontent.com", "GitHub Actions", "token.actions.githubusercontent.com:sub"},
		{"gitlab.com", "GitLab CI", "gitlab.com:sub"},
		{"app.terraform.io", "Terraform Cloud", "app.terraform.io:sub"},
		{"agent.buildkite.com", "Buildkite", "agent.buildkite.com:sub"},
		{"vstoken.actions.githubusercontent.com", "GitHub (vstoken)", "vstoken.actions.githubusercontent.com:sub"},
		{"oidc-configuration.audit-log.githubusercontent.com", "GitHub audit log streaming", "oidc-configuration.audit-log.githubusercontent.com:sub"},
		{"oidc.codefresh.io", "Codefresh", "oidc.codefresh.io:sub"},
		{"studio.datachain.ai/api", "DVC Studio", "studio.datachain.ai/api:sub"},
		{"scalr.io", "Scalr", "scalr.io:sub"},
		{"tokens.cloud.shisho.dev", "Shisho Cloud", "tokens.cloud.shisho.dev:sub"},
		{"proidc.upbound.io", "Upbound", "proidc.upbound.io:sub"},
		{"oidc.op1.openshiftapps.com/2f785sojlpb85i7402pk3qogugim5nfb", "IBM Turbonomic", "oidc.op1.openshiftapps.com/2f785sojlpb85i7402pk3qogugim5nfb:sub"},

		// Tenancy arrives in the audience for these four.
		{"oidc.vercel.com", "Vercel", "oidc.vercel.com:aud"},
		{"api.pulumi.com/oidc", "Pulumi Cloud", "api.pulumi.com/oidc:aud"},
		{"sandboxes.cloud", "sandboxes.cloud", "sandboxes.cloud:aud"},
		{"cognito-identity.amazonaws.com", "Amazon Cognito", "cognito-identity.amazonaws.com:aud"},

		// And in a global condition key for this one.
		{"sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d", "Azure Sentinel", "sts:RoleSessionName"},
	}

	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			if got := DisplayName(tt.issuer); got != tt.name {
				t.Errorf("DisplayName = %q, want %q", got, tt.name)
			}
			if got := TenancyConditionKey(tt.issuer); got != tt.tenancyKey {
				t.Errorf("TenancyConditionKey = %q, want %q", got, tt.tenancyKey)
			}
		})
	}
}

// A private issuer is not on anyone's shared list, and its URL is the thing
// that identifies the organization. It must still pin a subject.
func TestPrivateIssuerPinsOnSubject(t *testing.T) {
	const own = "oidc.internal.acme.example"
	if got := TenancyConditionKey(own); got != own+":sub" {
		t.Errorf("TenancyConditionKey = %q, want the subject key", got)
	}
}

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		sub       string
		kind      model.PartyKind
		scope     model.Scope
		org       string
		project   string
		orgID     string
		projectID string
		ref       string
		env       string
		display   string
	}{
		{
			name: "github exact ref", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:acme/api:ref:refs/heads/main",
			kind: model.PartyGitHub, scope: model.ScopeExact,
			org: "acme", project: "api", ref: "refs/heads/main",
			display: "github.com/acme/api @ refs/heads/main",
		},
		{
			name: "github environment", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:acme/api:environment:production",
			kind: model.PartyGitHub, scope: model.ScopeExact,
			org: "acme", project: "api", env: "production",
			display: "github.com/acme/api env production",
		},
		{
			name: "github pull request", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:acme/api:pull_request",
			kind: model.PartyGitHub, scope: model.ScopeProject,
			org: "acme", project: "api",
			display: "github.com/acme/api (pull_request)",
		},
		{
			name: "github job_workflow_ref", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:acme/api:job_workflow_ref:acme/shared/.github/workflows/deploy.yml@refs/heads/main",
			kind: model.PartyGitHub, scope: model.ScopeExact,
			org: "acme", project: "api", ref: "refs/heads/main",
		},
		{
			name: "github repo with no context admits any ref", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:acme/api:*",
			kind: model.PartyGitHub, scope: model.ScopeProject,
			org: "acme", project: "api",
			display: "github.com/acme/api (any ref)",
		},
		{
			name: "github org wide", issuer: "token.actions.githubusercontent.com",
			sub: "repo:acme/*", kind: model.PartyGitHub, scope: model.ScopeOrg,
			org: "acme", display: "ANY repository in github.com/acme",
		},
		{
			name: "github any repo anywhere", issuer: "token.actions.githubusercontent.com",
			sub: "repo:*", kind: model.PartyGitHub, scope: model.ScopeAnyone,
			org: "*", display: "ANY GitHub repository",
		},
		{
			name: "gitlab exact", issuer: "gitlab.com",
			sub:  "project_path:acme/infra:ref_type:branch:ref:main",
			kind: model.PartyGitLab, scope: model.ScopeExact,
			org: "acme", project: "acme/infra", ref: "main",
			display: "gitlab.com/acme/infra @ main",
		},
		{
			name: "gitlab any ref", issuer: "https://gitlab.com/",
			sub:  "project_path:acme/infra:ref_type:branch:ref:*",
			kind: model.PartyGitLab, scope: model.ScopeProject,
			org: "acme", project: "acme/infra", ref: "*",
		},
		{
			name: "circleci project", issuer: "oidc.circleci.com/org/2f1c3b44-aaaa-bbbb-cccc-1234567890ab",
			sub:  "org/2f1c3b44-aaaa-bbbb-cccc-1234567890ab/project/9988/user/7766",
			kind: model.PartyCircleCI, scope: model.ScopeExact,
			org: "2f1c3b44-aaaa-bbbb-cccc-1234567890ab", project: "9988",
		},
		{
			name: "terraform cloud workspace", issuer: "app.terraform.io",
			sub:  "organization:acme:project:platform:workspace:prod:run_phase:apply",
			kind: model.PartyTerraformCloud, scope: model.ScopeExact,
			org: "acme", project: "platform", env: "prod",
			display: "terraform cloud acme/prod (apply)",
		},
		{
			name: "terraform cloud any workspace", issuer: "app.terraform.io",
			sub:  "organization:acme:workspace:*:run_phase:apply",
			kind: model.PartyTerraformCloud, scope: model.ScopeOrg, org: "acme",
		},
		{
			name: "vercel production", issuer: "oidc.vercel.com/acme",
			sub:  "owner:acme:project:web:environment:production",
			kind: model.PartyVercel, scope: model.ScopeExact,
			org: "acme", project: "web", env: "production",
		},
		{
			name: "buildkite pipeline", issuer: "agent.buildkite.com",
			sub:  "organization:acme:pipeline:deploy:ref:refs/heads/main:commit:abc123:step:build",
			kind: model.PartyBuildkite, scope: model.ScopeExact,
			org: "acme", project: "deploy", ref: "refs/heads/main",
		},
		{
			name: "bitbucket uuids", issuer: "api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc",
			sub:  "{11111111-2222-3333-4444-555555555555}:{66666666-7777-8888-9999-000000000000}",
			kind: model.PartyBitbucket, scope: model.ScopeExact,
			project: "{11111111-2222-3333-4444-555555555555}",
		},
		{
			name: "google service account", issuer: "accounts.google.com",
			sub:  "109876543210987654321",
			kind: model.PartyGoogle, scope: model.ScopeExact,
		},
		{
			name: "unknown issuer falls back", issuer: "id.example.internal",
			sub: "svc-42", kind: model.PartyUnknown, scope: model.ScopeExact,
			display: "id.example.internal svc-42",
		},
		{
			name: "empty subject is anyone", issuer: "token.actions.githubusercontent.com",
			sub: "", kind: model.PartyGitHub, scope: model.ScopeAnyone,
			display: "ANY GitHub Actions tenant",
		},
		// GitHub's immutable subject format, issued for repositories created
		// after 15 July 2026. The ids must be split off so the report reads
		// normally, and kept so a fix can put them back.
		{
			name: "github immutable ref", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
			kind: model.PartyGitHub, scope: model.ScopeExact,
			org: "octo-org", project: "octo-repo",
			orgID: "123456", projectID: "456789",
			ref:     "refs/heads/main",
			display: "github.com/octo-org/octo-repo @ refs/heads/main",
		},
		{
			name: "github immutable environment", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:octo-org@123456/octo-repo@456789:environment:production",
			kind: model.PartyGitHub, scope: model.ScopeExact,
			org: "octo-org", project: "octo-repo",
			orgID: "123456", projectID: "456789",
			env:     "production",
			display: "github.com/octo-org/octo-repo env production",
		},
		{
			// Still org-wide: the numeric owner id does not narrow the repo.
			name: "github immutable org-wide is still org-wide", issuer: "token.actions.githubusercontent.com",
			sub:  "repo:octo-org@123456/*",
			kind: model.PartyGitHub, scope: model.ScopeOrg,
			org: "octo-org", orgID: "123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ParseSubject(tt.issuer, tt.sub)

			if p.Kind != tt.kind {
				t.Errorf("Kind = %q, want %q", p.Kind, tt.kind)
			}
			if p.Scope != tt.scope {
				t.Errorf("Scope = %q, want %q", p.Scope, tt.scope)
			}
			if tt.org != "" && p.Org != tt.org {
				t.Errorf("Org = %q, want %q", p.Org, tt.org)
			}
			if tt.project != "" && p.Project != tt.project {
				t.Errorf("Project = %q, want %q", p.Project, tt.project)
			}
			if tt.ref != "" && p.Ref != tt.ref {
				t.Errorf("Ref = %q, want %q", p.Ref, tt.ref)
			}
			if tt.env != "" && p.Environment != tt.env {
				t.Errorf("Environment = %q, want %q", p.Environment, tt.env)
			}
			if p.OrgID != tt.orgID {
				t.Errorf("OrgID = %q, want %q", p.OrgID, tt.orgID)
			}
			if p.ProjectID != tt.projectID {
				t.Errorf("ProjectID = %q, want %q", p.ProjectID, tt.projectID)
			}
			if tt.display != "" && p.Display != tt.display {
				t.Errorf("Display = %q, want %q", p.Display, tt.display)
			}
			if p.Display == "" {
				t.Error("Display is empty; every party must be describable in one line")
			}
			if p.Subject != tt.sub {
				t.Errorf("Subject = %q, want the raw sub preserved", p.Subject)
			}
		})
	}
}

func TestNormalizeIssuer(t *testing.T) {
	for in, want := range map[string]string{
		"https://gitlab.com/": "gitlab.com",
		"gitlab.com":          "gitlab.com",
		"http://token.actions.githubusercontent.com": "token.actions.githubusercontent.com",
		"  app.terraform.io  ":                       "app.terraform.io",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// A repository name that happens to contain a colon-separated word must not
// be misread as a context marker.
func TestGitHubSubUnknownContextKeepsRepo(t *testing.T) {
	p := ParseSubject("token.actions.githubusercontent.com", "repo:acme/api:workflow_ref:acme/api/.github/workflows/x.yml")
	if p.Org != "acme" || p.Project != "api" {
		t.Errorf("Org/Project = %q/%q", p.Org, p.Project)
	}
	if p.Scope != model.ScopeProject {
		t.Errorf("Scope = %q; an unparsed context must not be treated as exact", p.Scope)
	}
}
