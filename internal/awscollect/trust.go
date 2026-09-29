package awscollect

import (
	"strings"
	"time"

	"github.com/secorvia/frontdoor/internal/issuers"
	"github.com/secorvia/frontdoor/internal/model"
)

// trustInput is everything needed to turn one role into doors. It is a plain
// struct with no AWS types so the conversion can be unit-tested against
// fixture policies with no network and no credentials.
type trustInput struct {
	AccountID      string
	RoleARN        string
	RoleName       string
	RolePath       string
	Description    string
	Document       string // AssumeRolePolicyDocument, URL-encoded or raw JSON
	CreatedAt      *time.Time
	LastUsed       *time.Time
	LastUsedRegion string
	MaxSession     int32
	Tags           map[string]string

	// Providers is the account's identity providers keyed by ARN, used to
	// attach registered audiences and thumbprints to the door.
	Providers map[string]*model.IdentityProvider

	// IncludeService keeps AWS service-principal trusts, which are not doors
	// from outside the account and are dropped by default.
	IncludeService bool
}

// doorsFromTrustPolicy converts one role trust policy into zero or more doors.
// One statement can name several principals; each becomes its own door,
// because each is a separate way in.
// It also returns the same-account assume-role edges. Those are not doors -
// nobody outside the account is involved - but they are how a chain continues
// once someone is inside, and dropping them on the floor is how a scanner ends
// up reporting only the first hop.
func doorsFromTrustPolicy(in trustInput) ([]model.Door, []model.Hop, error) {
	doc, err := parsePolicyDocument(in.Document)
	if err != nil {
		return nil, nil, err
	}

	var doors []model.Door
	var edges []model.Hop
	for _, st := range doc.Statement {
		if !st.allows() || st.Principal.empty() {
			continue
		}
		conds := flattenConditions(st.Condition)

		for _, fed := range st.Principal.Federated {
			doors = append(doors, federatedDoor(in, st, conds, fed))
		}
		for _, aws := range st.Principal.AWS {
			if d, ok := crossAccountDoor(in, st, conds, aws); ok {
				doors = append(doors, d)
				continue
			}
			if e, ok := sameAccountEdge(in, st, aws); ok {
				edges = append(edges, e)
			}
		}
		if st.Principal.Anyone && len(st.Principal.AWS) == 0 {
			doors = append(doors, anyonedoor(in, st, conds))
		}
		if in.IncludeService {
			for _, svc := range st.Principal.Service {
				doors = append(doors, serviceDoor(in, st, conds, svc))
			}
		}
	}
	return doors, edges, nil
}

// sameAccountEdge records that one role in this account may assume another.
// AWS treats a trust policy naming a same-account principal as sufficient on
// its own, so this edge is real without also reading the calling identity's
// own policy.
func sameAccountEdge(in trustInput, st statement, principal string) (model.Hop, bool) {
	if principal == "*" || !strings.HasPrefix(principal, "arn:") {
		return model.Hop{}, false
	}
	if accountFromPrincipal(principal) != in.AccountID {
		return model.Hop{}, false
	}
	// Only identities can assume a role. A same-account principal that is not
	// a role or a user is something else entirely.
	if !strings.Contains(principal, ":role/") && !strings.Contains(principal, ":user/") {
		return model.Hop{}, false
	}
	if principal == in.RoleARN {
		return model.Hop{}, false // a role trusting itself goes nowhere
	}

	return model.Hop{
		Kind:         model.EdgeAssumeRole,
		From:         canonicalRoleARN(principal),
		To:           in.RoleARN,
		Via:          firstOr(st.Action, "sts:AssumeRole"),
		Provider:     model.ProviderAWS,
		FromProvider: model.ProviderAWS,
		Detail:       "can assume " + in.RoleName,
	}, true
}

// canonicalRoleARN turns an assumed-role session ARN back into the role ARN,
// which is how every other part of the graph addresses it.
//
//	arn:aws:sts::123:assumed-role/ci-deploy/session -> arn:aws:iam::123:role/ci-deploy
func canonicalRoleARN(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return arn
	}
	account := accountFromPrincipal(arn)
	if account == "" {
		return arn
	}
	rest := arn[strings.Index(arn, ":assumed-role/")+len(":assumed-role/"):]
	name := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		name = rest[:i]
	}
	return "arn:aws:iam::" + account + ":role/" + name
}

func firstOr(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return list[0]
}

// baseDoor fills the fields every door shares.
func baseDoor(in trustInput, st statement, conds []model.Condition) model.Door {
	return model.Door{
		Provider:          model.ProviderAWS,
		AccountID:         in.AccountID,
		ResourceARN:       in.RoleARN,
		ResourceName:      in.RoleName,
		NodeID:            in.RoleARN,
		StatementSID:      st.Sid,
		TrustActions:      append([]string(nil), st.Action...),
		Conditions:        conds,
		CreatedAt:         in.CreatedAt,
		LastUsed:          in.LastUsed,
		LastUsedRegion:    in.LastUsedRegion,
		MaxSessionSeconds: in.MaxSession,
		Description:       in.Description,
		Tags:              in.Tags,
	}
}

// federatedDoor handles "Principal": {"Federated": ...} - OIDC and SAML.
func federatedDoor(in trustInput, st statement, conds []model.Condition, fed string) model.Door {
	d := baseDoor(in, st, conds)

	switch {
	case strings.Contains(fed, ":oidc-provider/"):
		d.PrincipalType = model.PrincipalOIDC
		d.ProviderARN = fed
		d.Issuer = fed[strings.Index(fed, ":oidc-provider/")+len(":oidc-provider/"):]
	case strings.Contains(fed, ":saml-provider/"):
		d.PrincipalType = model.PrincipalSAML
		d.ProviderARN = fed
		d.Issuer = fed[strings.Index(fed, ":saml-provider/")+len(":saml-provider/"):]
	default:
		// Web identity shortcuts: cognito-identity.amazonaws.com,
		// accounts.google.com, graph.facebook.com, www.amazon.com.
		d.PrincipalType = model.PrincipalOIDC
		d.Issuer = fed
	}

	if p := in.Providers[d.ProviderARN]; p != nil {
		d.Audiences = p.Audiences
		d.Thumbprints = p.Thumbprints
		if p.EntityID != "" {
			d.Issuer = p.EntityID
		}
	}

	if d.PrincipalType == model.PrincipalSAML {
		d.ExternalParties = samlParties(d, conds)
	} else {
		d.ExternalParties = oidcParties(d.Issuer, conds)
	}
	return d
}

// oidcParties derives who may walk through an OIDC door from its sub
// conditions. No sub condition at all is the headline case: anyone the issuer
// will mint a token for.
//
// The condition key must be namespaced with this provider's own issuer -
// "token.actions.githubusercontent.com:sub". A condition written against a
// different namespace is a different door's key, and must not be read as if
// it constrained this one.
func oidcParties(issuer string, conds []model.Condition) []model.ExternalParty {
	subKey := issuers.Normalize(issuer) + ":sub"
	if subs := conditionValuesForKey(conds, subKey); len(subs) > 0 {
		out := make([]model.ExternalParty, 0, len(subs))
		for _, sub := range subs {
			out = append(out, issuers.ParseSubject(issuer, sub))
		}
		return out
	}
	// Keep this short: it becomes a finding title. The detail about which
	// condition key is missing belongs in the finding body, not the headline.
	return unconstrainedParties(conds, subKey, model.PartyUnknown,
		"ANY "+issuers.DisplayName(issuer)+" tenant", issuers.KindFor(issuer))
}

// samlParties describes a SAML door. SAML has no sub grammar to parse, so the
// party is the IdP itself, narrowed by any SAML:sub condition.
func samlParties(d model.Door, conds []model.Condition) []model.ExternalParty {
	subs := conditionValuesForKey(conds, "SAML:sub")
	if len(subs) == 0 {
		parties := unconstrainedParties(conds, "SAML:sub", model.PartySAMLIdP,
			"ANY user of SAML IdP "+d.Issuer, model.PartySAMLIdP)
		for i := range parties {
			parties[i].Org = d.Issuer
		}
		return parties
	}
	out := make([]model.ExternalParty, 0, len(subs))
	for _, s := range subs {
		out = append(out, model.ExternalParty{
			Kind:     model.PartySAMLIdP,
			Display:  "SAML IdP " + d.Issuer + " subject " + s,
			Subject:  s,
			Org:      d.Issuer,
			Scope:    issuers.ScopeFor(s),
			Wildcard: strings.ContainsAny(s, "*?"),
		})
	}
	return out
}

// crossAccountDoor handles "Principal": {"AWS": ...}. Same-account principals
// are not doors from outside and are dropped.
func crossAccountDoor(in trustInput, st statement, conds []model.Condition, principal string) (model.Door, bool) {
	if principal == "*" {
		return anyonedoor(in, st, conds), true
	}
	acct := accountFromPrincipal(principal)
	if acct == "" {
		// Unparseable principal: report it rather than drop it silently.
		d := baseDoor(in, st, conds)
		d.PrincipalType = model.PrincipalCrossAccount
		d.ExternalParties = []model.ExternalParty{{
			Kind:    model.PartyUnknown,
			Display: "unrecognised AWS principal " + principal,
			Subject: principal,
			Scope:   model.ScopeUnknown,
		}}
		return d, true
	}
	if acct == in.AccountID {
		return model.Door{}, false
	}

	d := baseDoor(in, st, conds)
	d.PrincipalType = model.PrincipalCrossAccount

	party := model.ExternalParty{
		Kind:      model.PartyAWSAccount,
		AccountID: acct,
		Subject:   principal,
		Scope:     model.ScopeAccount,
	}
	if v, ok := lookupVendor(acct); ok {
		party.Vendor = v.Name
		party.VendorRef = v.Source
		party.Display = v.Name + " (AWS account " + acct + ")"
	} else if hint := hintVendor(in.RoleName, in.RolePath, in.Description); hint != "" {
		party.Vendor = hint
		party.Display = "AWS account " + acct + " (possibly " + hint + ", matched on role name)"
	} else {
		party.Display = "AWS account " + acct
	}
	if !strings.HasSuffix(principal, ":root") && strings.Contains(principal, ":") {
		party.Display += " -> " + principal[strings.LastIndex(principal, ":")+1:]
		party.Scope = model.ScopeExact
	}
	d.ExternalParties = []model.ExternalParty{party}
	return d, true
}

// anyonedoor is "Principal": "*" or {"AWS": "*"} - the whole internet, subject
// only to whatever conditions the statement carries.
func anyonedoor(in trustInput, st statement, conds []model.Condition) model.Door {
	d := baseDoor(in, st, conds)
	d.PrincipalType = model.PrincipalCrossAccount
	d.ExternalParties = []model.ExternalParty{{
		Kind:     model.PartyAnyone,
		Display:  "ANY AWS principal (Principal: *)",
		Scope:    model.ScopeAnyone,
		Wildcard: true,
	}}
	return d
}

func serviceDoor(in trustInput, st statement, conds []model.Condition, svc string) model.Door {
	d := baseDoor(in, st, conds)
	d.PrincipalType = model.PrincipalService
	d.Issuer = svc
	d.ExternalParties = []model.ExternalParty{{
		Kind:    model.PartyAWSService,
		Display: "AWS service " + svc,
		Subject: svc,
		Scope:   model.ScopeExact,
	}}
	return d
}

// --- helpers ----------------------------------------------------------------

// flattenConditions turns the nested Condition block into a flat, stable list.
func flattenConditions(block conditionBlock) []model.Condition {
	var out []model.Condition
	for operator, keys := range block {
		for key, values := range keys {
			out = append(out, model.Condition{
				Operator: operator,
				Key:      key,
				Values:   append([]string(nil), values...),
			})
		}
	}
	sortConditions(out)
	return out
}

func sortConditions(c []model.Condition) {
	// Insertion sort: condition blocks have a handful of entries, and this
	// keeps output byte-stable across runs without pulling in a comparator.
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && condLess(c[j], c[j-1]); j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func condLess(a, b model.Condition) bool {
	if a.Key != b.Key {
		return a.Key < b.Key
	}
	return a.Operator < b.Operator
}

// unconstrainedParties describes a door whose subject claim is not constrained
// by any condition this provider will actually be evaluated against.
//
// Two very different situations end up here, and calling them the same thing
// would produce either a missed door or a false alarm:
//
//   - No subject condition at all, or only IfExists variants that pass
//     vacuously: the door is genuinely open to every tenant of the issuer.
//   - A subject condition written against a DIFFERENT issuer namespace: the
//     key is absent from the request context, so a plain StringEquals or
//     StringLike evaluates false and nobody gets through. That is a broken
//     door, not an open one, and is reported as such.
func unconstrainedParties(conds []model.Condition, wantKey string, fallbackKind model.PartyKind, openDisplay string, kind model.PartyKind) []model.ExternalParty {
	if kind == "" {
		kind = fallbackKind
	}

	var foreign []model.Condition
	allVacuous := true
	for _, c := range conds {
		if !strings.HasSuffix(strings.ToLower(c.Key), ":sub") {
			continue
		}
		if strings.EqualFold(c.Key, wantKey) {
			continue
		}
		foreign = append(foreign, c)
		if !strings.HasSuffix(strings.ToLower(c.Operator), "ifexists") {
			allVacuous = false
		}
	}

	if len(foreign) > 0 && !allVacuous {
		keys := make([]string, 0, len(foreign))
		for _, c := range foreign {
			keys = append(keys, c.Key)
		}
		return []model.ExternalParty{{
			Kind:  kind,
			Scope: model.ScopeUnknown,
			Display: "no condition on " + wantKey + "; the policy constrains " +
				strings.Join(keys, ", ") + " instead, which AWS does not evaluate for this provider",
		}}
	}

	return []model.ExternalParty{{
		Kind:     kind,
		Scope:    model.ScopeAnyone,
		Display:  openDisplay,
		Wildcard: true,
	}}
}

// conditionValuesForKey returns the values of the condition on exactly key,
// matched case-insensitively because IAM condition keys are case-insensitive.
func conditionValuesForKey(conds []model.Condition, key string) []string {
	var out []string
	for _, c := range conds {
		if strings.EqualFold(c.Key, key) {
			out = append(out, c.Values...)
		}
	}
	return out
}

// hasConditionKey reports whether any condition constrains the exact key.
func hasConditionKey(conds []model.Condition, key string) bool {
	for _, c := range conds {
		if strings.EqualFold(c.Key, key) {
			return true
		}
	}
	return false
}

// accountFromPrincipal extracts the account id from an AWS principal, which
// may be a bare account id, an ARN, or a root ARN.
func accountFromPrincipal(p string) string {
	if isAccountID(p) {
		return p
	}
	if !strings.HasPrefix(p, "arn:") {
		return ""
	}
	parts := strings.SplitN(p, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	if isAccountID(parts[4]) {
		return parts[4]
	}
	return ""
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
