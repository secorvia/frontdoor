package gcpcollect

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/issuers"
	"github.com/secorvia/frontdoor/internal/model"
)

// GCP writes who-may-do-what as an IAM member string. Most of them are
// ordinary ("serviceAccount:x@y.iam.gserviceaccount.com"), but the federation
// ones carry the whole story in a URL:
//
//	principalSet://iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/POOL/*
//	principalSet://.../workloadIdentityPools/POOL/attribute.repository/acme/api
//	principal://.../workloadIdentityPools/POOL/subject/repo:acme/api:ref:refs/heads/main
//
// The trailing "/*" is the one that matters: it binds every identity the pool
// will ever admit, so the pool's attributeCondition becomes the only gate.

const wifPrefix = "iam.googleapis.com/"

// MemberKind classifies an IAM member string.
type MemberKind int

const (
	MemberOther MemberKind = iota
	MemberFederated
	MemberServiceAccount
	MemberUser
	MemberGroup
	MemberDomain
	MemberAllUsers
)

// Member is a parsed IAM member.
type Member struct {
	Raw  string
	Kind MemberKind

	// Federated members only.
	Pool       string // projects/N/locations/global/workloadIdentityPools/POOL
	PoolName   string // POOL
	Selector   string // "*", "subject/X", "attribute.repository/acme/api", "group/X"
	Attribute  string // repository, repository_owner, ...
	Value      string // the attribute or subject value
	EntirePool bool

	// Identity members.
	Email   string
	Project string // the project a service account belongs to
	Domain  string
}

// ParseMember reads one IAM member string.
func ParseMember(raw string) Member {
	m := Member{Raw: raw, Kind: MemberOther}

	switch {
	case raw == "allUsers", raw == "allAuthenticatedUsers":
		m.Kind = MemberAllUsers
		return m

	case strings.HasPrefix(raw, "principalSet://"), strings.HasPrefix(raw, "principal://"):
		m.Kind = MemberFederated
		parseFederatedMember(&m, raw)
		return m

	case strings.HasPrefix(raw, "serviceAccount:"):
		m.Kind = MemberServiceAccount
		m.Email = strings.TrimPrefix(raw, "serviceAccount:")
		m.Project = serviceAccountProject(m.Email)
		return m

	case strings.HasPrefix(raw, "user:"):
		m.Kind = MemberUser
		m.Email = strings.TrimPrefix(raw, "user:")
		if _, host, ok := strings.Cut(m.Email, "@"); ok {
			m.Domain = host
		}
		return m

	case strings.HasPrefix(raw, "group:"):
		m.Kind = MemberGroup
		m.Email = strings.TrimPrefix(raw, "group:")
		if _, host, ok := strings.Cut(m.Email, "@"); ok {
			m.Domain = host
		}
		return m

	case strings.HasPrefix(raw, "domain:"):
		m.Kind = MemberDomain
		m.Domain = strings.TrimPrefix(raw, "domain:")
		return m
	}
	return m
}

func parseFederatedMember(m *Member, raw string) {
	body := raw
	for _, prefix := range []string{"principalSet://", "principal://"} {
		body = strings.TrimPrefix(body, prefix)
	}
	body = strings.TrimPrefix(body, wifPrefix)

	marker := "/workloadIdentityPools/"
	i := strings.Index(body, marker)
	if i < 0 {
		// Workforce pools use a different path shape; record it rather than
		// silently misreading it as a workload pool.
		m.Selector = body
		return
	}
	m.Pool = body[:i+len(marker)]
	rest := body[i+len(marker):]

	poolName, selector, found := strings.Cut(rest, "/")
	m.PoolName = poolName
	m.Pool += poolName
	if !found {
		// Binding names the pool with no selector at all.
		m.EntirePool = true
		return
	}
	m.Selector = selector

	switch {
	case selector == "*":
		m.EntirePool = true
	case strings.HasPrefix(selector, "subject/"):
		m.Attribute = "subject"
		m.Value = strings.TrimPrefix(selector, "subject/")
	case strings.HasPrefix(selector, "group/"):
		m.Attribute = "group"
		m.Value = strings.TrimPrefix(selector, "group/")
	case strings.HasPrefix(selector, "attribute."):
		attr, value, _ := strings.Cut(strings.TrimPrefix(selector, "attribute."), "/")
		m.Attribute = attr
		m.Value = value
	}
}

// serviceAccountProject extracts the project from a service account email.
// Default service accounts (PROJECTNUM-compute@developer.gserviceaccount.com)
// do not carry one, and saying "unknown" beats guessing.
func serviceAccountProject(email string) string {
	_, host, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	project, suffix, ok := strings.Cut(host, ".")
	if !ok || suffix != "iam.gserviceaccount.com" {
		return ""
	}
	return project
}

// PartyFor turns a member into an external party, using the provider behind
// the pool so a GitHub subject reads as a repository rather than as a URL
// fragment - and so an AWS-type provider resolves to the role ARN the AWS
// collector already knows about. prov may be nil when the pool has none.
func PartyFor(m Member, prov *model.IdentityProvider) model.ExternalParty {
	issuer := ""
	if prov != nil {
		issuer = prov.URL
		if prov.Type == model.PrincipalSAML && prov.EntityID != "" {
			issuer = prov.EntityID
		}
	}
	switch m.Kind {
	case MemberAllUsers:
		scope := model.ScopeAnyone
		display := "ANY Google account (allAuthenticatedUsers)"
		if m.Raw == "allUsers" {
			display = "ANYONE, authenticated or not (allUsers)"
		}
		return model.ExternalParty{
			Kind: model.PartyAnyone, Display: display, Scope: scope,
			Subject: m.Raw, Wildcard: true,
		}

	case MemberServiceAccount:
		return model.ExternalParty{
			Kind: model.PartyGCPServiceAcct, Display: "GCP service account " + m.Email,
			Scope: model.ScopeExact, Subject: m.Raw, Project: m.Project, Org: m.Project,
		}

	case MemberUser:
		return model.ExternalParty{
			Kind: model.PartyGoogleAccount, Display: "Google account " + m.Email,
			Scope: model.ScopeExact, Subject: m.Raw, Org: m.Domain,
		}

	case MemberGroup:
		return model.ExternalParty{
			Kind: model.PartyGoogleGroup, Display: "Google group " + m.Email,
			Scope: model.ScopeOrg, Subject: m.Raw, Org: m.Domain,
		}

	case MemberDomain:
		return model.ExternalParty{
			Kind: model.PartyGoogleDomain, Display: "EVERYONE in the domain " + m.Domain,
			Scope: model.ScopeDomain, Subject: m.Raw, Org: m.Domain, Wildcard: true,
		}

	case MemberFederated:
		return federatedParty(m, prov, issuer)
	}

	return model.ExternalParty{
		Kind: model.PartyUnknown, Display: "unrecognised IAM member " + m.Raw,
		Scope: model.ScopeUnknown, Subject: m.Raw,
	}
}

func federatedParty(m Member, prov *model.IdentityProvider, issuer string) model.ExternalParty {
	pool := m.PoolName
	if pool == "" {
		pool = "the pool"
	}

	// An AWS-type provider speaks AWS, not OIDC subjects. Handing its values
	// to the GitHub grammar would render an ARN as a repository name.
	if prov != nil && prov.Type == model.PrincipalCrossAccount && !m.EntirePool && m.Value != "" {
		return awsParty(m.Value, pool)
	}

	// Binding the whole pool means the attributeCondition on the provider is
	// the only thing deciding who gets in. That is the GCP shape of FD001.
	if m.EntirePool {
		platform := issuers.DisplayName(issuer)
		display := "ANY identity in workload identity pool " + pool
		if platform != "" && issuer != "" {
			display = "ANY " + platform + " tenant (whole pool " + pool + ")"
		}
		return model.ExternalParty{
			Kind:    kindOr(issuers.KindFor(issuer), model.PartyWIFPool),
			Display: display, Scope: model.ScopeAnyone,
			Subject: m.Raw, Wildcard: true, Org: pool,
		}
	}

	switch m.Attribute {
	case "subject":
		p := issuers.ParseSubject(issuer, m.Value)
		p.Subject = m.Raw
		return p

	case "group":
		return model.ExternalParty{
			Kind:    kindOr(issuers.KindFor(issuer), model.PartyWIFPool),
			Display: "group " + m.Value + " in pool " + pool,
			Scope:   model.ScopeOrg, Subject: m.Raw, Org: m.Value,
		}
	}

	// A mapped attribute. The common ones carry the same meaning as the parts
	// of a GitHub subject, so they get the same scope.
	p := model.ExternalParty{
		Kind:     kindOr(issuers.KindFor(issuer), model.PartyWIFPool),
		Subject:  m.Raw,
		Wildcard: strings.ContainsAny(m.Value, "*?"),
	}
	switch m.Attribute {
	case "repository", "project_path", "project":
		p.Project = m.Value
		p.Scope = model.ScopeProject
		if org, _, ok := strings.Cut(m.Value, "/"); ok {
			p.Org = org
		}
		p.Display = m.Value + " (any ref)"
	case "repository_owner", "namespace_path", "organization", "owner":
		p.Org = m.Value
		p.Scope = model.ScopeOrg
		p.Display = "ANY project owned by " + m.Value
	case "ref", "branch":
		p.Ref = m.Value
		p.Scope = model.ScopeOrg
		p.Display = "ANY project on ref " + m.Value
	case "environment":
		p.Environment = m.Value
		p.Scope = model.ScopeOrg
		p.Display = "ANY project in environment " + m.Value
	case "aws_role", "aws_account":
		p.Kind = model.PartyAWSAccount
		p.AccountID = m.Value
		p.Scope = model.ScopeAccount
		p.Display = "AWS " + m.Attribute + " " + m.Value
	default:
		p.Scope = model.ScopeUnknown
		p.Display = "pool " + pool + " where " + m.Attribute + " = " + m.Value
	}
	return p
}

func kindOr(k, fallback model.PartyKind) model.PartyKind {
	if k == "" {
		return fallback
	}
	return k
}
