// Package issuers parses the subject claims that OIDC providers put in their
// tokens. Every CI platform invents its own grammar for "who is calling", and
// turning that string into "the main branch of acme/api" is what separates a
// list of ARNs from an answer.
//
// It is provider-neutral on purpose: an AWS trust policy and a GCP workload
// identity binding carry the same GitHub subject, so both collectors parse it
// the same way.
package issuers

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// Each OIDC issuer encodes "who is calling" into the sub claim with its own
// grammar. Parsing it is what turns "some token" into "the main branch of
// acme/api" - the difference between a list of ARNs and an answer.

type issuerSpec struct {
	Kind model.PartyKind
	Name string
	// Match reports whether a normalized issuer host belongs to this provider.
	Match func(issuer string) bool
	// Parse turns one sub value into a party.
	Parse func(sub string, p *model.ExternalParty)
}

var issuerSpecs = []issuerSpec{
	{
		Kind: model.PartyGitHub, Name: "GitHub Actions",
		Match: func(i string) bool { return i == "token.actions.githubusercontent.com" },
		Parse: parseGitHubSub,
	},
	{
		Kind: model.PartyGitLab, Name: "GitLab CI",
		Match: func(i string) bool { return i == "gitlab.com" || strings.HasPrefix(i, "gitlab.") },
		Parse: parseGitLabSub,
	},
	{
		Kind: model.PartyCircleCI, Name: "CircleCI",
		Match: func(i string) bool { return strings.HasPrefix(i, "oidc.circleci.com") },
		Parse: parseCircleCISub,
	},
	{
		Kind: model.PartyTerraformCloud, Name: "Terraform Cloud",
		Match: func(i string) bool { return i == "app.terraform.io" || strings.HasSuffix(i, ".terraform.io") },
		Parse: parseTerraformCloudSub,
	},
	{
		Kind: model.PartyVercel, Name: "Vercel",
		Match: func(i string) bool { return strings.HasPrefix(i, "oidc.vercel.com") },
		Parse: parseVercelSub,
	},
	{
		Kind: model.PartyBuildkite, Name: "Buildkite",
		Match: func(i string) bool { return i == "agent.buildkite.com" },
		Parse: parseBuildkiteSub,
	},
	{
		Kind: model.PartyBitbucket, Name: "Bitbucket Pipelines",
		Match: func(i string) bool { return strings.HasPrefix(i, "api.bitbucket.org") },
		Parse: parseBitbucketSub,
	},
	{
		Kind: model.PartyGoogle, Name: "Google",
		Match: func(i string) bool { return i == "accounts.google.com" || i == "oauth2.googleapis.com" },
		Parse: parseGoogleSub,
	},
	{
		Kind: model.PartyCognito, Name: "Amazon Cognito",
		Match: func(i string) bool { return strings.HasPrefix(i, "cognito-identity.amazonaws.com") },
	},
}

// normalizeIssuer is model.NormalizeIssuer, aliased for brevity in this
// package where it is used on nearly every line.
func Normalize(s string) string { return model.NormalizeIssuer(s) }

// audienceTenancy lists the shared OIDC providers where the tenant is named by
// the *audience* claim rather than the subject. AWS calls the required claim an
// "identity-provider control" and refuses to create or update a trust policy
// for one of these issuers unless that claim is evaluated.
//
// This matters because a correctly configured role for one of them carries no
// subject condition at all. Reading the absent subject as "anyone may enter"
// would put a critical on a role built exactly the way AWS demands, which is
// the most expensive kind of wrong a scanner can be.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html
var audienceTenancy = []string{
	"oidc.vercel.com",
	"api.pulumi.com/oidc",
	"sandboxes.cloud",
	"cognito-identity.amazonaws.com",
}

// TenancyClaim is the claim that identifies *which tenant* of this issuer is on
// the other side of the door: "sub" for almost everything, "aud" for the
// providers listed above.
//
// Issuers AWS does not treat as shared get "sub" too. For a private issuer the
// URL itself identifies the organization, so a missing subject condition is
// still worth reporting, and defaulting the other way would hide real findings.
func TenancyClaim(issuer string) string {
	n := Normalize(issuer)
	for _, a := range audienceTenancy {
		if n == a || strings.HasPrefix(n, a+"/") {
			return "aud"
		}
	}
	return "sub"
}

func specForIssuer(issuer string) *issuerSpec {
	n := Normalize(issuer)
	for i := range issuerSpecs {
		if issuerSpecs[i].Match(n) {
			return &issuerSpecs[i]
		}
	}
	return nil
}

// issuerDisplayName returns a friendly platform name, or the raw issuer.
func DisplayName(issuer string) string {
	if s := specForIssuer(issuer); s != nil {
		return s.Name
	}
	return Normalize(issuer)
}

// parseSubject builds a party from one sub-condition value. A value that is
// empty, "*", or starts with a wildcard admits effectively anyone on that
// platform, and is reported as such rather than mis-parsed into a repo name.
func ParseSubject(issuer, sub string) model.ExternalParty {
	spec := specForIssuer(issuer)
	p := model.ExternalParty{
		Kind:     model.PartyUnknown,
		Subject:  sub,
		Wildcard: strings.ContainsAny(sub, "*?"),
		Scope:    model.ScopeUnknown,
	}
	if spec != nil {
		p.Kind = spec.Kind
	}

	if sub == "" || sub == "*" || strings.HasPrefix(sub, "*") {
		p.Scope = model.ScopeAnyone
		p.Wildcard = true
		if spec != nil {
			p.Display = "ANY " + spec.Name + " tenant"
		} else {
			p.Display = "ANY identity from " + Normalize(issuer)
		}
		return p
	}

	// Kubernetes is recognised by its subject, not its issuer: every cluster
	// gets its own OIDC URL, so there is no host to match on. EKS, AKS and GKE
	// all mint the same "system:serviceaccount:NAMESPACE:NAME" shape, which is
	// why this check sits outside the issuer table.
	if strings.HasPrefix(sub, "system:serviceaccount:") {
		parseKubernetesSub(sub, &p)
		return p
	}

	if spec != nil && spec.Parse != nil {
		spec.Parse(sub, &p)
	}
	if p.Display == "" {
		p.Display = Normalize(issuer) + " " + sub
	}
	if p.Scope == model.ScopeUnknown {
		p.Scope = ScopeFor(sub)
	}
	return p
}

// scopeFor is the fallback narrowing: a literal value pins one identity,
// a globbed one does not.
func ScopeFor(s string) model.Scope {
	if s == "" || strings.ContainsAny(s, "*?") {
		return model.ScopeProject
	}
	return model.ScopeExact
}

// --- per-issuer sub grammars -------------------------------------------------

// GitHub Actions:
//
//	repo:ORG/REPO:ref:refs/heads/main
//	repo:ORG/REPO:environment:production
//	repo:ORG/REPO:pull_request
//	repo:ORG/REPO:job_workflow_ref:ORG/REPO/.github/workflows/x.yml@refs/heads/main
//	repo:ORG/*                      org-wide
//
// Repositories created after 15 July 2026 use an immutable form that appends a
// numeric id to the owner and the repository, separated by "@":
//
//	repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main
//
// "@" cannot appear in a GitHub owner or repository name, so splitting on it is
// unambiguous. The ids are kept in OrgID and ProjectID rather than discarded:
// the display wants the plain name, and any fix we emit has to carry the ids
// back or it will not match the token.
// splitImmutableName separates "octo-repo@456789" into the name and the id.
// A name with no "@" is the legacy form and yields an empty id.
func splitImmutableName(s string) (name, id string) {
	n, i, found := strings.Cut(s, "@")
	if !found {
		return s, ""
	}
	return n, i
}

func parseGitHubSub(sub string, p *model.ExternalParty) {
	rest, ok := strings.CutPrefix(sub, "repo:")
	if !ok {
		// Enterprise installs and custom issuer claims land here.
		p.Display = "github " + sub
		p.Scope = ScopeFor(sub)
		return
	}

	// The repo is ORG/REPO; whatever follows the next colon is the context.
	name := rest
	ctx := ""
	if n, c, found := strings.Cut(rest, ":"); found {
		name, ctx = n, c
	}
	if org, repo, found := strings.Cut(name, "/"); found {
		p.Org, p.OrgID = splitImmutableName(org)
		p.Project, p.ProjectID = splitImmutableName(repo)
	} else {
		p.Org, p.OrgID = splitImmutableName(name)
	}

	switch {
	case strings.HasPrefix(ctx, "ref:"):
		p.Ref = strings.TrimPrefix(ctx, "ref:")
	case strings.HasPrefix(ctx, "environment:"):
		p.Environment = strings.TrimPrefix(ctx, "environment:")
	case strings.HasPrefix(ctx, "job_workflow_ref:"):
		p.Workflow = strings.TrimPrefix(ctx, "job_workflow_ref:")
		if _, ref, found := strings.Cut(p.Workflow, "@"); found {
			p.Ref = ref
		}
	case strings.HasPrefix(ctx, "pull_request"):
		p.PullRequest = true
	}

	if p.Org == "" || strings.ContainsAny(p.Org, "*?") {
		p.Scope = model.ScopeAnyone
		p.Display = "ANY GitHub repository"
		return
	}
	if p.Project == "" || strings.ContainsAny(p.Project, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY repository in github.com/" + p.Org
		return
	}

	discriminator := p.Ref + p.Environment + p.Workflow
	switch {
	case p.PullRequest:
		// A pull_request token is issued for forks too, depending on settings.
		p.Scope = model.ScopeProject
	case discriminator == "" || strings.ContainsAny(discriminator, "*?"):
		p.Scope = model.ScopeProject
	default:
		p.Scope = model.ScopeExact
	}

	p.Display = "github.com/" + p.Org + "/" + p.Project
	switch {
	case p.PullRequest:
		p.Display += " (pull_request)"
	case p.Ref != "":
		p.Display += " @ " + p.Ref
	case p.Environment != "":
		p.Display += " env " + p.Environment
	default:
		p.Display += " (any ref)"
	}
}

// GitLab CI: project_path:GROUP/PROJECT:ref_type:branch:ref:main
func parseGitLabSub(sub string, p *model.ExternalParty) {
	fields := strings.Split(sub, ":")
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "project_path":
			p.Project = fields[i+1]
			if group, _, ok := strings.Cut(fields[i+1], "/"); ok {
				p.Org = group
			}
		case "namespace_path", "group_path":
			p.Org = fields[i+1]
		case "ref":
			p.Ref = fields[i+1]
		case "environment":
			p.Environment = fields[i+1]
		}
	}
	switch {
	case p.Project == "":
		p.Scope = model.ScopeOrg
		p.Display = "ANY project in gitlab group " + p.Org
	case strings.ContainsAny(p.Project, "*?"):
		p.Scope = model.ScopeOrg
		p.Display = "gitlab " + p.Project
	case p.Ref == "" || strings.ContainsAny(p.Ref, "*?"):
		p.Scope = model.ScopeProject
		p.Display = "gitlab.com/" + p.Project + " (any ref)"
	default:
		p.Scope = model.ScopeExact
		p.Display = "gitlab.com/" + p.Project + " @ " + p.Ref
	}
}

// CircleCI: org/ORG-UUID/project/PROJECT-UUID/user/USER-UUID
func parseCircleCISub(sub string, p *model.ExternalParty) {
	fields := strings.Split(strings.Trim(sub, "/"), "/")
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "org":
			p.Org = fields[i+1]
		case "project":
			p.Project = fields[i+1]
		case "user":
			p.Actor = fields[i+1]
		}
	}
	if p.Project == "" || strings.ContainsAny(p.Project, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY CircleCI project in org " + p.Org
		return
	}
	p.Scope = model.ScopeExact
	p.Display = "circleci org " + p.Org + " project " + p.Project
}

// Terraform Cloud: organization:ORG:project:PROJ:workspace:WS:run_phase:apply
func parseTerraformCloudSub(sub string, p *model.ExternalParty) {
	fields := strings.Split(sub, ":")
	runPhase := ""
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "organization":
			p.Org = fields[i+1]
		case "project":
			p.Project = fields[i+1]
		case "workspace":
			p.Environment = fields[i+1]
		case "run_phase":
			runPhase = fields[i+1]
		}
	}
	if p.Environment == "" || strings.ContainsAny(p.Environment, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY workspace in Terraform Cloud org " + p.Org
		return
	}
	p.Scope = model.ScopeExact
	p.Display = "terraform cloud " + p.Org + "/" + p.Environment
	if runPhase != "" {
		p.Display += " (" + runPhase + ")"
	}
}

// Vercel: owner:TEAM:project:PROJ:environment:production
func parseVercelSub(sub string, p *model.ExternalParty) {
	fields := strings.Split(sub, ":")
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "owner":
			p.Org = fields[i+1]
		case "project":
			p.Project = fields[i+1]
		case "environment":
			p.Environment = fields[i+1]
		}
	}
	if p.Project == "" || strings.ContainsAny(p.Project, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY Vercel project in team " + p.Org
		return
	}
	p.Scope = ScopeFor(p.Environment)
	p.Display = "vercel " + p.Org + "/" + p.Project
	if p.Environment != "" {
		p.Display += " env " + p.Environment
	}
}

// Buildkite: organization:ORG:pipeline:PIPE:ref:refs/heads/main:commit:SHA:step:STEP
func parseBuildkiteSub(sub string, p *model.ExternalParty) {
	fields := strings.Split(sub, ":")
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "organization":
			p.Org = fields[i+1]
		case "pipeline":
			p.Project = fields[i+1]
		}
	}
	// ref carries colons of its own (refs/heads/main), so take it as a tail.
	if _, tail, ok := strings.Cut(sub, ":ref:"); ok {
		p.Ref = strings.SplitN(tail, ":commit:", 2)[0]
	}
	if p.Project == "" || strings.ContainsAny(p.Project, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY pipeline in buildkite org " + p.Org
		return
	}
	p.Scope = ScopeFor(p.Ref)
	p.Display = "buildkite " + p.Org + "/" + p.Project
	if p.Ref != "" {
		p.Display += " @ " + p.Ref
	}
}

// Bitbucket Pipelines: REPO-UUID:ENVIRONMENT-UUID:STEP-UUID
// The UUIDs are opaque; report them rather than pretend to resolve them.
func parseBitbucketSub(sub string, p *model.ExternalParty) {
	fields := strings.Split(sub, ":")
	if len(fields) > 0 {
		p.Project = fields[0]
	}
	if len(fields) > 1 {
		p.Environment = fields[1]
	}
	if p.Project == "" || strings.ContainsAny(p.Project, "*?") {
		p.Scope = model.ScopeOrg
		p.Display = "ANY Bitbucket repository in the workspace"
		return
	}
	p.Scope = model.ScopeExact
	p.Display = "bitbucket repository " + p.Project
}

// Google: sub is the service account unique numeric id. This is the
// AWS <-> GCP federation edge Phase 5 follows across clouds.
func parseGoogleSub(sub string, p *model.ExternalParty) {
	p.Actor = sub
	p.Scope = model.ScopeExact
	p.Display = "GCP service account (unique id " + sub + ")"
}

// KindFor returns the party kind for a known issuer, or the empty kind when
// the issuer is not one we have a grammar for.
func KindFor(issuer string) model.PartyKind {
	if s := specForIssuer(issuer); s != nil {
		return s.Kind
	}
	return ""
}

// Kubernetes: system:serviceaccount:NAMESPACE:SERVICEACCOUNT
//
// A cluster service account is as exact as a subject gets, but the namespace
// matters for the reader: "default" is where anything anyone deploys without
// thinking about it ends up.
func parseKubernetesSub(sub string, p *model.ExternalParty) {
	p.Kind = model.PartyKubernetes

	rest := strings.TrimPrefix(sub, "system:serviceaccount:")
	namespace, name, found := strings.Cut(rest, ":")
	p.Org = namespace
	p.Project = name

	switch {
	case !found || name == "" || strings.ContainsAny(name, "*?"):
		p.Scope = model.ScopeOrg
		p.Display = "ANY service account in namespace " + orUnknown(namespace)
	case strings.ContainsAny(namespace, "*?"):
		p.Scope = model.ScopeOrg
		p.Display = "service account " + name + " in ANY namespace"
	default:
		p.Scope = model.ScopeExact
		p.Display = "k8s " + namespace + "/" + name
	}
}

func orUnknown(s string) string {
	if s == "" || s == "*" {
		return "any namespace"
	}
	return s
}
