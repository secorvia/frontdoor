package rules

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/issuers"
	"github.com/secorvia/frontdoor/internal/model"
)

// conditionIsWildcard reports whether a condition names nothing in particular:
// no values at all, or every value a bare glob. Such a condition is present in
// the policy but constrains nobody, so it must not be read as a pin.
func conditionIsWildcard(c model.Condition) bool {
	if len(c.Values) == 0 {
		return true
	}
	for _, v := range c.Values {
		if v != "" && v != "*" && !strings.HasPrefix(v, "*") {
			return false
		}
	}
	return true
}

// federatedRules covers the OIDC and SAML doors: FD001, FD002, FD003, FD005,
// FD010, FD011, FD012 and FD015.
func (c *evalContext) federatedRules(d *model.Door) {
	subKey := d.SubjectConditionKey()
	audKey := d.AudienceConditionKey()
	_, hasAud := d.ConditionFor(audKey)
	held := narrowingConditions(d)

	// On a few shared providers AWS names explicitly, the tenant is identified
	// by something other than the subject: the audience for Vercel, Pulumi,
	// sandboxes.cloud and Cognito, and sts:RoleSessionName for Azure Sentinel.
	// A correct trust policy for one of those carries no subject condition at
	// all, so the pinned tenancy claim is the door being shut, not left open.
	tenancyPinned := false
	if d.PrincipalType == model.PrincipalOIDC {
		if key := issuers.TenancyConditionKey(d.Issuer); key != subKey {
			cond, ok := d.ConditionFor(key)
			if ok && !conditionIsWildcard(cond) {
				tenancyPinned = true
				subKey = key
			}
		}
	}

	openSubject := false
	for i := range d.ExternalParties {
		p := &d.ExternalParties[i]
		switch p.Scope {
		case model.ScopeAnyone:
			if tenancyPinned {
				// The audience names the tenant, so this door is not open.
				continue
			}
			openSubject = true
			c.fd001(d, p, subKey, held)
		case model.ScopeUnknown:
			c.fd005(d, p, subKey)
		case model.ScopeOrg:
			c.fd010(d, p)
		case model.ScopeProject:
			c.fd011(d, p)
		}
		if p.PullRequest {
			c.fd012(d, p)
		}
	}

	if !hasAud && d.PrincipalType == model.PrincipalOIDC {
		c.fd002(d, audKey, openSubject)
	}
	c.fd015(d, subKey)

	if (openSubject || !hasAud) && d.IsPrivileged && d.PrincipalType == model.PrincipalOIDC {
		c.fd003(d, openSubject, hasAud)
	}
}

// FD001 - the door has no effective constraint on who is on the other side.
func (c *evalContext) fd001(d *model.Door, p *model.ExternalParty, subKey string, held []string) {
	sev := model.SeverityCritical
	wrong := "The trust policy places no condition on " + subKey +
		", so the subject claim is never checked."
	attacker := "Anyone able to get a token from " + model.NormalizeIssuer(d.Issuer) +
		" - which on a public CI platform means anyone at all - can assume this role and use everything it grants."

	if d.PrincipalType == model.PrincipalSAML {
		// A SAML trust admits every user of your own IdP. That is too wide,
		// but it is not the open internet, and calling it critical alongside
		// "any GitHub repository" would flatten a real difference.
		sev = model.SeverityHigh
		attacker = "Any user your identity provider will authenticate - including a contractor, a dormant " +
			"account, or anyone who phishes one of them - can assume this role."
	}
	if len(held) > 0 {
		// A door held open by nothing is not the same as one held by
		// aws:PrincipalOrgID. Calling both critical would train people to
		// ignore the word.
		sev = model.SeverityHigh
		wrong += " The only thing narrowing it is " + strings.Join(held, ", ") + "."
	}

	f := fromDoor(d, "FD001", sev, p.Display+" can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = wrong
	f.AttackerCan = attacker
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary:     "Pin the subject claim to the exact identity you intend to trust.",
		TrustPolicy: trustPolicyFix(d, p),
		Steps: []string{
			"Confirm which repository, workspace or pipeline is supposed to use this role.",
			"Add the " + subKey + " condition below to the trust policy statement.",
			"Re-run frontdoor to confirm the door now names one identity.",
		},
	}
	c.add(f)
}

// FD002 - no audience condition. Severity is contextual: with no subject
// condition either, any token from the issuer works, and that is the critical
// case. With the subject pinned, this is hardening.
func (c *evalContext) fd002(d *model.Door, audKey string, openSubject bool) {
	sev := model.SeverityMedium
	extra := "The subject claim is pinned, so this is defence in depth rather than an open door."
	switch {
	case openSubject:
		sev = model.SeverityCritical
		extra = "Combined with the missing subject condition, any token this issuer has ever minted is accepted."
	case c.subjectIsBroad(d):
		sev = model.SeverityHigh
		extra = "The subject condition is broad, so the audience check is the only other thing in the way."
	}

	f := fromDoor(d, "FD002", sev, "No audience check on "+short(d.ResourceARN))
	f.WhatIsWrong = "The trust policy has no condition on " + audKey +
		", so a token minted for a different relying party is accepted. " + extra
	f.AttackerCan = "Replay a token that " + model.NormalizeIssuer(d.Issuer) +
		" issued for some other service against AWS, instead of having to obtain one issued for AWS."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary:     "Add the audience condition registered on the identity provider.",
		TrustPolicy: newCond().eq(audKey, audienceFor(d)).render(),
		Steps: []string{
			"Check the client IDs registered on the OIDC provider (identity_providers[].audiences in the JSON).",
			"Add the " + audKey + " condition to every statement that trusts this provider.",
		},
	}
	c.add(f)
}

// FD003 - an open door on a role that can escalate.
func (c *evalContext) fd003(d *model.Door, openSubject, hasAud bool) {
	cause := "its audience claim is not checked"
	if openSubject {
		cause = "its subject claim is not checked"
		if !hasAud {
			cause = "neither its subject nor its audience claim is checked"
		}
	}

	f := fromDoor(d, "FD003", model.SeverityCritical,
		"Open door into a privileged role: "+short(d.ResourceARN))
	f.WhatIsWrong = "This role can be assumed from outside because " + cause +
		", and it holds permissions that can be escalated to account takeover."
	f.AttackerCan = "Assume the role from outside, then escalate - " + firstReason(d.PrivilegeReasons) +
		". That turns one CI token into persistent control of the account."
	f.Evidence = append(append([]string{}, d.PrivilegeReasons...), doorEvidence(d)...)
	f.Fix = model.Fix{
		Summary: "Close the door (FD001/FD002) and cut the role's permissions to what the pipeline actually needs.",
		Steps: []string{
			"Fix the trust policy first - see FD001 and FD002 on this same role.",
			"Remove the privilege-escalation permissions listed in the evidence, or scope them to specific resources.",
			"If the pipeline genuinely needs iam:PassRole, restrict it with iam:PassedToService and an explicit role ARN.",
		},
	}
	c.add(f)
}

// FD005 - the subject condition names a claim from a different issuer. AWS
// does not put that key in the request context for this provider, so a plain
// StringEquals evaluates false and nobody can assume the role. This is not a
// finding the spec asked for; it falls out of parsing the namespace correctly
// and would otherwise be reported as a wide-open door, which it is not.
func (c *evalContext) fd005(d *model.Door, p *model.ExternalParty, subKey string) {
	var foreign []string
	for _, cond := range d.Conditions {
		if strings.HasSuffix(strings.ToLower(cond.Key), ":sub") && !strings.EqualFold(cond.Key, subKey) {
			foreign = append(foreign, cond.Key)
		}
	}

	f := fromDoor(d, "FD005", model.SeverityMedium,
		"Subject condition is namespaced to the wrong issuer on "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The statement constrains " + strings.Join(foreign, ", ") + " but the provider is " +
		model.NormalizeIssuer(d.Issuer) + ", so AWS never populates that key and the condition always fails."
	f.AttackerCan = "Nothing - this door currently admits nobody. The risk is the opposite: the role cannot be " +
		"assumed at all, and whoever fixes the resulting outage may reach for a wildcard."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary:     "Rename the condition key to this provider's own issuer.",
		TrustPolicy: trustPolicyFix(d, p),
		Steps: []string{
			"The condition key prefix must exactly match the OIDC provider URL, without the scheme.",
			"Expected prefix for this role: " + model.NormalizeIssuer(d.Issuer),
		},
	}
	c.add(f)
}

// FD010 - any repository in the org, including one created after the review.
func (c *evalContext) fd010(d *model.Door, p *model.ExternalParty) {
	f := fromDoor(d, "FD010", model.SeverityHigh,
		"Org-wide trust: "+p.Display+" can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The subject condition matches every project in " + orDefault(p.Org, "the organization") +
		", not one project. New and forked-in repositories inherit this access automatically."
	f.AttackerCan = "Get write access to any single repository in the org - or persuade someone to create one - " +
		"and assume this role from it."
	f.Evidence = subjectEvidence(d, p)
	f.Fix = model.Fix{
		Summary:     "Name the specific project instead of the organization.",
		TrustPolicy: trustPolicyFix(d, p),
		Steps: []string{
			"If several projects share the role, list each subject explicitly rather than globbing the org.",
			"If the list would be long, give each project its own role.",
		},
	}
	c.add(f)
}

// FD011 - the project is pinned but any branch or tag in it can assume.
func (c *evalContext) fd011(d *model.Door, p *model.ExternalParty) {
	if !refCapable(p.Kind) {
		return
	}
	f := fromDoor(d, "FD011", model.SeverityHigh,
		"Any branch of "+p.Display+" can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The subject condition pins the repository but not the ref, so a workflow on any branch or " +
		"tag can assume this role."
	f.AttackerCan = "Push a branch to the repository - which anyone with write access, including a compromised " +
		"contributor account, can do without review - and assume the role from it."
	f.Evidence = subjectEvidence(d, p)
	f.Fix = model.Fix{
		Summary:     "Pin the ref, or use a protected deployment environment.",
		TrustPolicy: trustPolicyFix(d, p),
		Steps: []string{
			"Prefer an environment condition (repo:ORG/REPO:environment:production) with required reviewers, " +
				"which survives branch renames.",
			"Otherwise pin the ref to refs/heads/main and protect that branch.",
		},
	}
	c.add(f)
}

// FD012 - the pull_request context is accepted.
func (c *evalContext) fd012(d *model.Door, p *model.ExternalParty) {
	f := fromDoor(d, "FD012", model.SeverityHigh,
		"Pull-request workflows can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The subject condition accepts the pull_request context. GitHub issues that same subject " +
		"for every pull request in the repository, with no pull-request number, source branch or author in it, " +
		"so the condition cannot tell one pull request from another."
	f.AttackerCan = "Open a pull request and have the workflow it triggers assume this role. Required reviews " +
		"and branch protection do not apply, because the token is issued before anything is merged."
	f.Evidence = subjectEvidence(d, p)
	f.Fix = model.Fix{
		Summary:     "Restrict the subject to a ref or a protected environment instead of the pull_request context.",
		TrustPolicy: trustPolicyFix(d, p),
		Steps: []string{
			"Check which workflow needs this role, and whether it has to run on pull requests at all.",
			"Move deployment credentials to a workflow that only runs on a protected branch or environment.",
			"If a pull-request workflow does need cloud access, give it a separate role scoped to a test account.",
		},
	}
	c.add(f)
}

// FD015 - repository_owner is a name, and names can change hands.
func (c *evalContext) fd015(d *model.Door, subKey string) {
	ownerKey := d.ClaimConditionKey("repository_owner")
	if ownerKey == "" {
		return
	}
	owner, hasOwner := d.ConditionFor(ownerKey)
	if !hasOwner {
		return
	}
	if _, hasSub := d.ConditionFor(subKey); hasSub {
		return // the subject is pinned; repository_owner is then belt and braces
	}
	if _, hasOwnerID := d.ConditionFor(d.ClaimConditionKey("repository_owner_id")); hasOwnerID {
		return // the numeric id is stable and cannot be re-registered
	}

	f := fromDoor(d, "FD015", model.SeverityHigh,
		"Trust rests on the organization name alone: "+short(d.ResourceARN))
	f.WhatIsWrong = "The only constraint is " + ownerKey + ", a display name rather than a stable id, and it " +
		"admits every repository owned by that account."
	f.AttackerCan = "Register the name if the organization is ever renamed or deleted, or exploit a lookalike " +
		"in a policy that also globs - and then assume the role from a repository they control."
	f.Evidence = []string{conditionEvidence(owner)}
	f.Fix = model.Fix{
		Summary: "Condition on the subject claim, and on repository_owner_id rather than the name.",
		TrustPolicy: newCond().
			eq(d.AudienceConditionKey(), audienceFor(d)).
			eq(subKey, "repo:"+firstValue(owner)+"/YOUR_REPO:ref:refs/heads/main").
			render(),
		Steps: []string{
			"Find the numeric owner id from the OIDC token claims and condition on " +
				d.ClaimConditionKey("repository_owner_id") + " instead of the name.",
		},
	}
	c.add(f)
}

// --- helpers -----------------------------------------------------------------

// subjectIsBroad reports whether any party on the door is wider than one project.
func (c *evalContext) subjectIsBroad(d *model.Door) bool {
	for _, p := range d.ExternalParties {
		if p.Scope == model.ScopeOrg || p.Scope == model.ScopeUnknown {
			return true
		}
	}
	return false
}

// refCapable reports whether the platform has a branch/tag concept worth
// pinning. Flagging "no ref restriction" on a platform without refs would be
// nonsense.
func refCapable(k model.PartyKind) bool {
	switch k {
	case model.PartyGitHub, model.PartyGitLab, model.PartyBuildkite:
		return true
	}
	return false
}

func subjectEvidence(d *model.Door, p *model.ExternalParty) []string {
	if p.Subject != "" {
		return []string{d.SubjectConditionKey() + " = " + p.Subject}
	}
	return doorEvidence(d)
}

// firstReason returns the consequence half of a privilege reason, so it reads
// as a clause. The reasons are phrased "grants iam:PassRole: can pass any
// role..."; only the part after the colon composes into a sentence.
func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return "it can use everything the role grants"
	}
	r := reasons[0]
	if _, consequence, ok := strings.Cut(r, ": "); ok {
		return consequence
	}
	return r
}

func firstValue(c model.Condition) string {
	if len(c.Values) == 0 {
		return "YOUR_ORG"
	}
	return strings.TrimSuffix(c.Values[0], "*")
}

// short trims a resource identifier to the part a human reads.
func short(id string) string { return model.ShortName(id) }
