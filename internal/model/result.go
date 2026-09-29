package model

import "time"

// Result is the whole output of a scan. Every collector appends to it.
type Result struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`

	Accounts []Account `json:"accounts"`
	Doors    []Door    `json:"doors"`

	// Findings are produced by the rule engine from Doors. Empty when the
	// scan was run for collection only.
	Findings []Finding `json:"findings"`
	Counts   Counts    `json:"counts"`

	// Chains are paths from an outside identity to what it can ultimately
	// reach. Populated by the chain rules.
	Chains []Chain `json:"chains,omitempty"`

	// Principals is every node the graph can pass through, whether or not it
	// has a door of its own.
	Principals []Principal `json:"principals,omitempty"`

	IdentityProviders []IdentityProvider `json:"identity_providers"`
	AccessKeys        []AccessKey        `json:"access_keys,omitempty"`

	// Unreadable is every API call that was denied or failed. It is part of the
	// output on purpose: a scan that silently skipped half the account would be
	// worse than useless.
	Unreadable []Unreadable `json:"unreadable,omitempty"`
}

// Account is a cloud account the scan touched or learned about.
type Account struct {
	Provider  Provider `json:"provider"`
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Alias     string   `json:"alias,omitempty"`
	Scanned   bool     `json:"scanned"`
	InOrg     bool     `json:"in_org"`
	OrgID     string   `json:"org_id,omitempty"`
	Status    string   `json:"status,omitempty"`
	CallerARN string   `json:"caller_arn,omitempty"`
}

// IdentityProvider is a federation provider registered in the account,
// whether or not any role references it.
type IdentityProvider struct {
	Provider    Provider      `json:"provider"`
	AccountID   string        `json:"account_id"`
	ARN         string        `json:"arn"`
	Type        PrincipalType `json:"type"`
	URL         string        `json:"url,omitempty"`       // OIDC issuer URL
	EntityID    string        `json:"entity_id,omitempty"` // SAML IdP entityID
	Audiences   []string      `json:"audiences,omitempty"`
	Thumbprints []string      `json:"thumbprints,omitempty"`
	CreatedAt   *time.Time    `json:"created_at,omitempty"`
	ValidUntil  *time.Time    `json:"valid_until,omitempty"`

	// GCP workload identity federation detail. AttributeCondition is the CEL
	// expression that decides which outside identities the provider admits.
	// It is kept verbatim because our parse of it is a heuristic and the
	// reader must be able to check our work.
	Pool               string            `json:"pool,omitempty"`
	AttributeCondition string            `json:"attribute_condition,omitempty"`
	AttributeMapping   map[string]string `json:"attribute_mapping,omitempty"`
	Disabled           bool              `json:"disabled,omitempty"`

	// ReferencedBy is every resource whose trust policy or IAM binding names
	// this provider. Empty means the provider is dead weight (FD021).
	ReferencedBy []string `json:"referenced_by"`
}

// AccessKey is a long-lived IAM user key. Collected because a federated
// account that still hands out static keys has not actually moved off them
// (Phase 2 FD020). On GCP these are user-managed service account keys, which
// are the same mistake under a different name.
type AccessKey struct {
	Provider    Provider   `json:"provider,omitempty"`
	AccountID   string     `json:"account_id"`
	UserName    string     `json:"user_name"`
	UserARN     string     `json:"user_arn,omitempty"`
	AccessKeyID string     `json:"access_key_id"`
	Status      string     `json:"status"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	LastService string     `json:"last_service,omitempty"`
	LastRegion  string     `json:"last_region,omitempty"`
}

// AgeDays returns how old the key is, or -1 if unknown.
func (k AccessKey) AgeDays(now time.Time) int {
	if k.CreatedAt == nil {
		return -1
	}
	return int(now.Sub(*k.CreatedAt).Hours() / 24)
}

// Unreadable records one thing the scan could not read and why.
type Unreadable struct {
	Provider  Provider `json:"provider"`
	AccountID string   `json:"account_id,omitempty"`
	Operation string   `json:"operation"`          // iam:ListRoles
	Resource  string   `json:"resource,omitempty"` // ARN or name, when known
	Code      string   `json:"code,omitempty"`     // AccessDenied
	Message   string   `json:"message"`
	Denied    bool     `json:"denied"` // true = permissions, false = other failure
}

// AddUnreadable appends a gap, de-duplicated on operation+resource+code.
func (r *Result) AddUnreadable(u Unreadable) {
	for _, e := range r.Unreadable {
		if e.Operation == u.Operation && e.Resource == u.Resource && e.Code == u.Code {
			return
		}
	}
	r.Unreadable = append(r.Unreadable, u)
}
