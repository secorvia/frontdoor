package model

// Severity ranks a finding. The order matters: --fail-on compares against it.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// Rank returns a comparable weight; unknown severities sort lowest.
func (s Severity) Rank() int { return severityRank[s] }

// AtLeast reports whether s is as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// ParseSeverity accepts the names used on the command line.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(s)
	if _, ok := severityRank[sev]; ok {
		return sev, true
	}
	return "", false
}

// Fix is the remediation for one finding. TrustPolicy is a JSON fragment the
// user can paste; it is generated from the door's real issuer and, where the
// tool knows them, the real org and repository.
type Fix struct {
	Summary     string   `json:"summary"`
	TrustPolicy string   `json:"trust_policy,omitempty"`
	Steps       []string `json:"steps,omitempty"`
}

// Finding is one problem with one door.
type Finding struct {
	ID       string   `json:"id"` // FD001
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`

	Provider     Provider `json:"provider"`
	AccountID    string   `json:"account_id"`
	ResourceARN  string   `json:"resource_arn"`
	ResourceName string   `json:"resource_name,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`

	// ExternalParty is the party this finding is about, when the door admits
	// several and only one of them is the problem.
	ExternalParty string `json:"external_party,omitempty"`

	WhatIsWrong string `json:"what_is_wrong"`
	AttackerCan string `json:"what_an_attacker_could_do"`

	// Evidence is the exact policy text the finding rests on, so nobody has to
	// take the tool's word for it.
	Evidence []string `json:"evidence,omitempty"`

	Fix     Fix    `json:"fix"`
	DocsURL string `json:"docs_url,omitempty"`

	Suppressed     bool   `json:"suppressed,omitempty"`
	SuppressReason string `json:"suppress_reason,omitempty"`
}

// Counts summarises findings for the report footer.
type Counts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	Total      int `json:"total"`
	Suppressed int `json:"suppressed"`
}

// Tally counts findings by severity, excluding suppressed ones from the
// severity buckets but counting them separately.
func Tally(findings []Finding) Counts {
	var c Counts
	for _, f := range findings {
		if f.Suppressed {
			c.Suppressed++
			continue
		}
		c.Total++
		switch f.Severity {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		case SeverityInfo:
			c.Info++
		}
	}
	return c
}

// NormalizeIssuer strips scheme and trailing slash so "https://gitlab.com/"
// and "gitlab.com" compare equal. IAM stores OIDC provider URLs without a
// scheme, but trust policies and condition keys both appear in the wild.
func NormalizeIssuer(s string) string {
	s = trimSpace(s)
	for _, prefix := range []string{"https://", "http://"} {
		if len(s) >= len(prefix) && equalFold(s[:len(prefix)], prefix) {
			s = s[len(prefix):]
			break
		}
	}
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

// SubjectConditionKey is the condition key that constrains WHO may use this
// door. For OIDC it is namespaced with the provider's own issuer; a condition
// written against any other namespace is not evaluated by AWS for this
// provider and therefore does not constrain it.
func (d Door) SubjectConditionKey() string {
	switch d.PrincipalType {
	case PrincipalOIDC:
		return NormalizeIssuer(d.Issuer) + ":sub"
	case PrincipalSAML:
		return "SAML:sub"
	default:
		return ""
	}
}

// AudienceConditionKey is the condition key that constrains WHICH TOKEN is
// accepted through this door.
func (d Door) AudienceConditionKey() string {
	switch d.PrincipalType {
	case PrincipalOIDC:
		return NormalizeIssuer(d.Issuer) + ":aud"
	case PrincipalSAML:
		return "SAML:aud"
	default:
		return ""
	}
}

// ClaimConditionKey namespaces any other OIDC claim, e.g. "repository_owner".
func (d Door) ClaimConditionKey(claim string) string {
	if d.PrincipalType != PrincipalOIDC {
		return ""
	}
	return NormalizeIssuer(d.Issuer) + ":" + claim
}

// ConditionFor returns the condition on exactly key, if present.
func (d Door) ConditionFor(key string) (Condition, bool) {
	if key == "" {
		return Condition{}, false
	}
	for _, c := range d.Conditions {
		if equalFold(c.Key, key) {
			return c, true
		}
	}
	return Condition{}, false
}
