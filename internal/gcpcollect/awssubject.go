package gcpcollect

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// A GCP workload identity pool can federate from AWS. When it does, the
// subject GCP sees is the caller's assumed-role ARN:
//
//	arn:aws:sts::111122223333:assumed-role/ci-deploy/some-session
//
// That string is the seam between the two clouds. Parsing it into the role ARN
// the AWS collector already knows about is what turns two separate scans into
// one graph - and it is the only reason a chain can start in a GitHub
// repository, pass through an AWS role, and end in a GCP service account.

// awsParty describes an AWS caller admitted by a GCP AWS-type provider. The
// NodeRef it returns is the canonical role ARN, which is how the AWS side of
// the graph addresses the same identity.
func awsParty(value, poolDisplay string) model.ExternalParty {
	p := model.ExternalParty{
		Kind:     model.PartyAWSAccount,
		Subject:  value,
		Wildcard: strings.ContainsAny(value, "*?"),
	}

	roleARN, account, name := parseAWSSubject(value)
	p.AccountID = account
	p.NodeRef = roleARN

	switch {
	case roleARN != "":
		p.Scope = model.ScopeExact
		p.Project = name
		p.Org = account
		p.Display = "AWS role " + name + " in account " + account
	case account != "":
		p.Scope = model.ScopeAccount
		p.Org = account
		p.Display = "ANY role in AWS account " + account
	default:
		p.Scope = model.ScopeUnknown
		p.Display = "AWS caller " + value + " (pool " + poolDisplay + ")"
	}
	return p
}

// parseAWSSubject reads an AWS principal as GCP presents it and returns the
// canonical role ARN, the account id, and the role name. A value that names
// only an account yields an empty role ARN rather than a guessed one.
func parseAWSSubject(value string) (roleARN, account, name string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", ""
	}

	// A bare account id.
	if isAccountID(value) {
		return "", value, ""
	}
	if !strings.HasPrefix(value, "arn:") {
		return "", "", ""
	}

	parts := strings.SplitN(value, ":", 6)
	if len(parts) < 6 {
		return "", "", ""
	}
	account = parts[4]
	if !isAccountID(account) {
		return "", "", ""
	}
	resource := parts[5]

	switch {
	case strings.HasPrefix(resource, "assumed-role/"):
		name = strings.TrimPrefix(resource, "assumed-role/")
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[:i] // drop the session name
		}
	case strings.HasPrefix(resource, "role/"):
		name = strings.TrimPrefix(resource, "role/")
	default:
		return "", account, ""
	}

	if name == "" || strings.ContainsAny(name, "*?") {
		return "", account, name
	}
	return "arn:aws:iam::" + account + ":role/" + name, account, name
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
