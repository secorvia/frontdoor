// Package model defines the provider-neutral shapes every collector produces.
//
// A Door is one way in: a single trust-policy statement (AWS), workload
// identity provider (GCP) or federated credential (Azure) that lets an
// identity living OUTSIDE the account obtain credentials INSIDE it.
package model

import "time"

// Provider is the cloud the door was found in.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// PrincipalType is the mechanism the door uses.
type PrincipalType string

const (
	PrincipalOIDC         PrincipalType = "oidc"
	PrincipalSAML         PrincipalType = "saml"
	PrincipalCrossAccount PrincipalType = "cross_account"
	PrincipalService      PrincipalType = "service"
)

// PartyKind identifies who stands on the outside of the door.
type PartyKind string

const (
	PartyGitHub         PartyKind = "github_actions"
	PartyGitLab         PartyKind = "gitlab_ci"
	PartyCircleCI       PartyKind = "circleci"
	PartyTerraformCloud PartyKind = "terraform_cloud"
	PartyVercel         PartyKind = "vercel"
	PartyBuildkite      PartyKind = "buildkite"
	PartyBitbucket      PartyKind = "bitbucket_pipelines"
	PartyGoogle         PartyKind = "google"
	PartyCognito        PartyKind = "cognito"
	PartyAWSAccount     PartyKind = "aws_account"
	PartyGCPServiceAcct PartyKind = "gcp_service_account"
	PartyGoogleAccount  PartyKind = "google_account"
	PartyGoogleGroup    PartyKind = "google_group"
	PartyGoogleDomain   PartyKind = "google_domain"
	PartyWIFPool        PartyKind = "workload_identity_pool"
	PartyKubernetes     PartyKind = "kubernetes"
	PartyEntraTenant    PartyKind = "entra_tenant"
	PartyEntraGuest     PartyKind = "entra_guest"
	PartySAMLIdP        PartyKind = "saml_idp"
	PartyAWSService     PartyKind = "aws_service"
	PartyAnyone         PartyKind = "anyone"
	PartyUnknown        PartyKind = "unknown"
)

// Condition is one condition clause on the door, kept verbatim so rules can
// reason about what is and is not constrained.
type Condition struct {
	Operator string   `json:"operator"` // StringEquals, StringLike, ForAllValues:StringEquals, ...
	Key      string   `json:"key"`      // token.actions.githubusercontent.com:sub
	Values   []string `json:"values"`
}

// HasWildcard reports whether any value in the clause contains a glob.
func (c Condition) HasWildcard() bool {
	for _, v := range c.Values {
		if containsGlob(v) {
			return true
		}
	}
	return false
}

func containsGlob(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

// ExternalParty is one outside identity the door admits, as precisely as the
// conditions allow us to describe it. A door with no subject condition yields
// a single party with Wildcard set and Scope ScopeAnyone.
type ExternalParty struct {
	Kind    PartyKind `json:"kind"`
	Display string    `json:"display"` // human line, e.g. "github.com/acme/api @ refs/heads/main"
	Scope   Scope     `json:"scope"`

	Subject string `json:"subject,omitempty"` // raw sub value this was parsed from

	Org         string `json:"org,omitempty"`         // GitHub org, GitLab group, TFC org, Buildkite org
	Project     string `json:"project,omitempty"`     // repo / project path / pipeline
	Ref         string `json:"ref,omitempty"`         // refs/heads/main
	Environment string `json:"environment,omitempty"` // deployment environment / TFC workspace
	Workflow    string `json:"workflow,omitempty"`    // job_workflow_ref
	Actor       string `json:"actor,omitempty"`

	// OrgID and ProjectID carry the numeric ids GitHub puts in the immutable
	// subject format it issues for repositories created after 15 July 2026:
	//
	//	repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main
	//
	// Org and Project keep the plain names so the report stays readable. The
	// ids are kept separately because a fix we suggest has to reproduce the
	// exact shape the issuer sends; drop them and the condition stops matching,
	// which breaks the caller's pipeline instead of securing it.
	OrgID     string `json:"org_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`

	PullRequest bool `json:"pull_request,omitempty"` // sub admits pull_request context

	AccountID string `json:"account_id,omitempty"` // cross-account trusts

	// NodeRef is set when this party is itself an identity inside a cloud we
	// scanned - an AWS role federating into a GCP project, say. It is the
	// canonical node id of that identity, and it is what lets a chain cross
	// from one cloud into another instead of stopping at the border.
	NodeRef   string `json:"node_ref,omitempty"`
	Vendor    string `json:"vendor,omitempty"`     // resolved SaaS vendor name
	VendorRef string `json:"vendor_ref,omitempty"` // doc URL backing the vendor label

	Wildcard bool `json:"wildcard"` // the subject pattern contains a glob

	// Internal is set when this party turned out to be an identity inside a
	// cloud this same scan covered. The door is real, but it is a seam in the
	// middle of a chain rather than a way in from outside, and counting it as
	// an entry point would report the same path twice.
	Internal bool `json:"internal,omitempty"`
}

// Scope says how wide the admitted set is. Phase 2 rules key off this.
type Scope string

const (
	ScopeExact   Scope = "exact"   // one repo, one ref
	ScopeProject Scope = "project" // one repo, any ref
	ScopeOrg     Scope = "org"     // any repo in one org
	ScopeAnyone  Scope = "anyone"  // any customer of the issuer
	ScopeDomain  Scope = "domain"  // everyone in one Google Workspace domain
	ScopeAccount Scope = "account" // an entire AWS account
	ScopeUnknown Scope = "unknown"
)

// PolicySource records where a set of granted actions came from.
type PolicySource struct {
	Type    string `json:"type"` // managed | inline
	Name    string `json:"name"`
	ARN     string `json:"arn,omitempty"`
	Unread  bool   `json:"unread,omitempty"` // listed but could not be read
	Message string `json:"message,omitempty"`
}

// Door is one entrance into a cloud account from outside it.
type Door struct {
	Provider     Provider `json:"provider"`
	AccountID    string   `json:"account_id"`
	ResourceARN  string   `json:"resource_arn"`
	ResourceName string   `json:"resource_name"`

	// NodeID is this resource as the trust graph addresses it: the role ARN on
	// AWS, the service account email on GCP. Collectors set it, because only
	// they know which of their identifiers is globally unique.
	NodeID string `json:"node_id,omitempty"`

	PrincipalType PrincipalType `json:"principal_type"`
	Issuer        string        `json:"issuer,omitempty"`

	ExternalParties []ExternalParty `json:"external_parties"`
	Conditions      []Condition     `json:"conditions"`
	GrantedActions  []string        `json:"granted_actions"`
	IsPrivileged    bool            `json:"is_privileged"`

	PrivilegeReasons []string `json:"privilege_reasons,omitempty"`

	// Provider detail, carried so rules and output do not have to re-derive it.
	StatementSID    string         `json:"statement_sid,omitempty"`
	TrustActions    []string       `json:"trust_actions,omitempty"` // sts:AssumeRoleWithWebIdentity, ...
	Policies        []PolicySource `json:"policies,omitempty"`
	PoliciesPartial bool           `json:"policies_partial,omitempty"` // at least one policy unreadable
	ProviderARN     string         `json:"provider_arn,omitempty"`     // the OIDC/SAML provider resource
	Audiences       []string       `json:"audiences,omitempty"`        // client IDs registered on the provider
	Thumbprints     []string       `json:"thumbprints,omitempty"`

	CreatedAt         *time.Time        `json:"created_at,omitempty"`
	LastUsed          *time.Time        `json:"last_used,omitempty"`
	LastUsedRegion    string            `json:"last_used_region,omitempty"`
	MaxSessionSeconds int32             `json:"max_session_seconds,omitempty"`
	Description       string            `json:"description,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// IsExternal reports whether the door admits an identity from outside the
// account. Service-principal doors are collected but are not external.
func (d Door) IsExternal() bool {
	return d.PrincipalType != PrincipalService
}

// HasConditionKey reports whether any condition constrains key, case-insensitively.
func (d Door) HasConditionKey(key string) bool {
	for _, c := range d.Conditions {
		if equalFold(c.Key, key) {
			return true
		}
	}
	return false
}

// ConditionsForSuffix returns every condition whose key ends in suffix
// (":sub", ":aud"), which is how OIDC claim conditions are namespaced.
func (d Door) ConditionsForSuffix(suffix string) []Condition {
	var out []Condition
	for _, c := range d.Conditions {
		if len(c.Key) >= len(suffix) && equalFold(c.Key[len(c.Key)-len(suffix):], suffix) {
			out = append(out, c)
		}
	}
	return out
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
