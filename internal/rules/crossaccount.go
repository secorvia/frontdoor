package rules

import (
	"github.com/secorvia/frontdoor/internal/model"
)

// crossAccountRules covers trusts to another AWS account: FD013 and FD014,
// plus the wide-open Principal:* case, which is FD001 by another route.
func (c *evalContext) crossAccountRules(d *model.Door) {
	for i := range d.ExternalParties {
		p := &d.ExternalParties[i]

		if p.Kind == model.PartyAnyone {
			c.fd001Anyone(d, p)
			continue
		}
		if p.AccountID == "" {
			continue
		}
		c.fd013(d, p)
		c.fd014(d, p)
	}
}

// fd001Anyone is FD001 for "Principal": "*" - no federation involved, the
// statement simply names every AWS principal in existence.
func (c *evalContext) fd001Anyone(d *model.Door, p *model.ExternalParty) {
	held := narrowingConditions(d)

	sev := model.SeverityCritical
	wrong := "The statement names every AWS principal and places no narrowing condition on it."
	attacker := "Assume this role from any AWS account in the world, including one created for the purpose."
	if len(held) > 0 {
		sev = model.SeverityHigh
		wrong = "The statement names every AWS principal. The only thing narrowing it is " +
			joinAnd(held) + "."
		attacker = "Assume this role from anywhere that satisfies " + joinAnd(held) +
			", which is a much larger set than the one principal you meant to trust."
	}

	f := fromDoor(d, "FD001", sev, "Any AWS principal can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = wrong
	f.AttackerCan = attacker
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary: "Replace the wildcard principal with the exact account or role ARN you intend to trust.",
		TrustPolicy: "\"Principal\": { \"AWS\": \"arn:aws:iam::THE_ACCOUNT_YOU_TRUST:root\" },\n" +
			externalIDFix(),
		Steps: []string{
			"Identify which account actually assumes this role - check CloudTrail for AssumeRole events.",
			"Name that account or, better, the specific role ARN inside it.",
			"If the caller is a third party, also require sts:ExternalId (see FD013).",
		},
	}
	c.add(f)
}

// FD013 - the confused deputy. A third party that holds many customers' role
// ARNs can be tricked into assuming yours unless it must also present a secret
// only you and it know.
func (c *evalContext) fd013(d *model.Door, p *model.ExternalParty) {
	if _, ok := d.ConditionFor("sts:ExternalId"); ok {
		return
	}
	// A trust to a sibling account inside your own organization is not the
	// confused-deputy scenario: the third party is you.
	if c.orgAccounts[p.AccountID] {
		return
	}

	sev := model.SeverityHigh
	note := ""
	if !c.orgKnown() {
		// organizations:ListAccounts was denied, so we cannot prove this
		// account is a stranger. Say that rather than overstate it.
		sev = model.SeverityMedium
		note = " The organization layout could not be read, so frontdoor cannot confirm whether " +
			p.AccountID + " is one of your own accounts."
	}

	f := fromDoor(d, "FD013", sev,
		"Cross-account trust to "+p.AccountID+" has no ExternalId: "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "Account " + p.AccountID + " can assume this role knowing only its ARN, which is not a secret." + note
	f.AttackerCan = "Another customer of the same third party can ask it to assume your role ARN. The third " +
		"party is authorised, so AWS allows it, and your data is handed to them - the confused deputy problem."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary:     "Require an external id that the third party generates uniquely for you.",
		TrustPolicy: externalIDFix(),
		Steps: []string{
			"Ask the vendor for your external id - every vendor that asks for a cross-account role has one.",
			"Never invent the value yourself and never reuse it across vendors.",
			"If the caller is your own account, prefer naming its role ARN directly over an external id.",
		},
	}
	c.add(f)
}

// FD014 - a trust to an account that is neither yours nor a vendor we can
// identify. This is the "who is that?" finding.
func (c *evalContext) fd014(d *model.Door, p *model.ExternalParty) {
	if c.orgAccounts[p.AccountID] {
		return
	}
	if p.VendorRef != "" {
		return // identified from the vendor's own published account id
	}

	sev := model.SeverityHigh
	wrong := "Account " + p.AccountID + " is not in your organization and does not match any vendor account " +
		"id frontdoor knows about."
	if !c.orgKnown() {
		sev = model.SeverityMedium
		wrong = "Account " + p.AccountID + " does not match any vendor account id frontdoor knows about, and " +
			"organizations:ListAccounts was denied so its membership of your organization could not be checked."
	}
	if p.Vendor != "" {
		// A role-name hint is a guess, not an identification. It lowers the
		// odds this is a surprise, but it is not evidence.
		wrong += " The role name suggests " + p.Vendor + ", but that is a guess from the name, not a confirmed " +
			"account id."
	}

	f := fromDoor(d, "FD014", sev,
		"Unrecognised account "+p.AccountID+" can assume "+short(d.ResourceARN))
	f.ExternalParty = p.Display
	f.WhatIsWrong = wrong
	f.AttackerCan = "If this trust is stale or was never intended, whoever controls that account has standing " +
		"access to everything the role grants, and nothing in your own account will show it as unusual."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary: "Identify the account, then either document it or remove the trust.",
		Steps: []string{
			"Search CloudTrail for AssumeRole events on this role to see whether it is used at all.",
			"If it is a vendor, add it to your --vendors file so future scans label it instead of flagging it.",
			"If nobody can say what it is, remove the statement.",
		},
	}
	c.add(f)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, s := range items[:len(items)-1] {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out + " and " + items[len(items)-1]
}
