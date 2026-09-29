package rules

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// GCP federation is the same idea as an AWS trust policy wearing different
// clothes, so it maps onto the same rule ids. The differences that matter are
// the ones where copying AWS behaviour would produce a false alarm:
//
//   - GCP's default audience is the provider's own canonical resource name.
//     An empty allowedAudiences list is therefore SECURE, not missing. Firing
//     FD002 on it - which a literal reading of "no audience constraint" would
//     do - would flag the correct configuration on every provider there is.
//   - GCP does not report last-used for service account keys, so FD020 must
//     not say "never used" about a key it simply cannot see the usage of.
//   - GCP providers have no CA thumbprints at all, so FD022 does not apply.

// gcpRules evaluates one GCP door.
func (c *evalContext) gcpRules(d *model.Door) {
	prov := c.providerFor(d.ProviderARN)

	for i := range d.ExternalParties {
		p := &d.ExternalParties[i]
		switch p.Scope {
		case model.ScopeAnyone:
			c.fd001GCP(d, p, prov)
		case model.ScopeDomain:
			c.fd001GCPDomain(d, p)
		case model.ScopeOrg:
			c.fd010(d, p)
		case model.ScopeProject:
			c.fd011(d, p)
		case model.ScopeUnknown:
			if prov != nil && prov.AttributeCondition != "" {
				c.fd005GCP(d, p, prov)
			}
		}
		if p.PullRequest {
			c.fd012(d, p)
		}
	}

	c.fd002GCP(d, prov)

	if d.IsPrivileged && c.doorIsOpen(d) {
		c.fd003(d, true, len(d.Audiences) > 0)
	}
}

// providerFor looks up the workload identity provider behind a door.
func (c *evalContext) providerFor(arn string) *model.IdentityProvider {
	if arn == "" {
		return nil
	}
	for i := range c.res.IdentityProviders {
		if c.res.IdentityProviders[i].ARN == arn {
			return &c.res.IdentityProviders[i]
		}
	}
	return nil
}

func (c *evalContext) doorIsOpen(d *model.Door) bool {
	for _, p := range d.ExternalParties {
		switch p.Scope {
		case model.ScopeAnyone, model.ScopeDomain, model.ScopeOrg:
			return true
		}
	}
	return false
}

// FD001 on GCP: the binding names the whole pool and nothing narrows it.
func (c *evalContext) fd001GCP(d *model.Door, p *model.ExternalParty, prov *model.IdentityProvider) {
	pool := "the workload identity pool"
	condition := ""
	if prov != nil {
		if prov.Pool != "" {
			pool = shortPool(prov.Pool)
		}
		condition = prov.AttributeCondition
	}

	wrong := "The IAM binding grants " + orDefault(firstOrEmpty(d.TrustActions), "access") +
		" to every identity in " + pool + ", and the provider has no attributeCondition to narrow it."
	if condition != "" {
		wrong = "The IAM binding grants access to every identity in " + pool +
			", and the provider's attributeCondition does not constrain who the caller is."
	}

	f := fromDoor(d, "FD001", model.SeverityCritical, p.Display+" can become "+short(d.ResourceName))
	f.ExternalParty = p.Display
	f.WhatIsWrong = wrong
	f.AttackerCan = "Anyone who can get a token from " + orDefault(model.NormalizeIssuer(d.Issuer), "the configured issuer") +
		" can impersonate " + d.ResourceName + " and use everything it can reach."
	f.Evidence = gcpEvidence(d, prov)
	f.Fix = model.Fix{
		Summary:     "Bind one identity, not the pool, and add an attributeCondition.",
		TrustPolicy: gcpBindingFix(d, p, prov),
		Steps: []string{
			"Replace the pool-wide member (the one ending in /*) with a " +
				"principalSet://.../attribute.repository/YOUR_ORG/YOUR_REPO member, or a " +
				"principal://.../subject/EXACT_SUBJECT member.",
			"Set an attributeCondition on the provider, for example: " +
				"assertion.repository_owner == 'YOUR_ORG'",
			"Both together: the binding says which identity, the condition says which tokens are even accepted.",
		},
	}
	c.add(f)
}

// FD001 on a whole Google Workspace domain. Not federation, but the same
// mistake: a binding whose member is everyone.
func (c *evalContext) fd001GCPDomain(d *model.Door, p *model.ExternalParty) {
	f := fromDoor(d, "FD001", model.SeverityHigh,
		"Everyone in "+p.Org+" can use "+short(d.ResourceName))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The IAM binding names the domain " + p.Org +
		", so every account in that Workspace holds this grant."
	f.AttackerCan = "Use any account in the domain - a contractor, a leaver whose account is still open, " +
		"or anyone who phishes one of them - to reach " + short(d.ResourceName) + "."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary: "Name a group you actually manage, not the whole domain.",
		Steps: []string{
			"Replace domain:" + p.Org + " with a Google group whose membership is reviewed.",
			"If a domain-wide grant is genuinely intended, add an IAM condition to bound it.",
		},
	}
	c.add(f)
}

// FD002 on GCP. An empty allowedAudiences means the default: the provider's
// own canonical resource name, which is provider-specific and correct. The
// finding is for a CUSTOM audience that is not tied to this provider, because
// that is a token someone else's relying party might also accept.
func (c *evalContext) fd002GCP(d *model.Door, prov *model.IdentityProvider) {
	if prov == nil || prov.Type != model.PrincipalOIDC || len(prov.Audiences) == 0 {
		return
	}

	var shared []string
	for _, aud := range prov.Audiences {
		if audienceBoundToProvider(aud, prov) {
			continue
		}
		shared = append(shared, aud)
	}
	if len(shared) == 0 {
		return
	}

	sev := model.SeverityMedium
	if c.doorIsOpen(d) {
		sev = model.SeverityHigh
	}

	f := fromDoor(d, "FD002", sev, "Provider accepts an audience that is not its own: "+short(d.ResourceName))
	f.WhatIsWrong = "allowedAudiences contains " + strings.Join(shared, ", ") +
		", which is not this provider's canonical resource name. A token minted for that audience by " +
		"some other relying party is accepted here."
	f.AttackerCan = "Obtain a token issued for that shared audience - which may be far easier to come by " +
		"than one issued for this provider - and present it to GCP."
	f.Evidence = []string{"allowedAudiences = " + strings.Join(prov.Audiences, ", ")}
	f.Fix = model.Fix{
		Summary: "Remove the custom audience and let GCP use its secure default.",
		Steps: []string{
			"With allowedAudiences empty, GCP accepts only the provider's full resource name as the " +
				"audience, which is specific to this provider.",
			"If a custom audience is required, make it unique to this provider and never reuse it.",
		},
	}
	c.add(f)
}

// FD005 on GCP: an attributeCondition we could not read. Saying nothing would
// leave the reader thinking the door was checked; saying it is open would be a
// guess. So it says exactly what happened.
func (c *evalContext) fd005GCP(d *model.Door, p *model.ExternalParty, prov *model.IdentityProvider) {
	f := fromDoor(d, "FD005", model.SeverityLow,
		"Could not verify the attributeCondition on "+short(d.ResourceName))
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The provider has an attributeCondition, but frontdoor could not determine whether it " +
		"constrains the caller. It is reproduced below verbatim - check it yourself."
	f.AttackerCan = "Unknown. This finding is a gap in the tool, not a proven weakness."
	f.Evidence = []string{"attributeCondition: " + prov.AttributeCondition}
	f.Fix = model.Fix{
		Summary: "Confirm by hand that the condition pins the caller, not just the token's shape.",
		Steps: []string{
			"A condition that checks only assertion.aud or a timestamp does not say who is calling.",
			"If the condition is correct, this is a false positive worth reporting: " +
				"https://github.com/secorvia/frontdoor/issues",
		},
	}
	c.add(f)
}

// --- helpers -----------------------------------------------------------------

// audienceBoundToProvider reports whether an audience value is tied to this
// specific provider rather than shared with other relying parties.
func audienceBoundToProvider(aud string, prov *model.IdentityProvider) bool {
	if prov.ARN != "" && strings.Contains(aud, prov.ARN) {
		return true
	}
	if prov.Pool != "" && strings.Contains(aud, prov.Pool) {
		return true
	}
	// The canonical form GCP documents.
	return strings.Contains(aud, "/workloadIdentityPools/") && strings.Contains(aud, "/providers/")
}

func gcpEvidence(d *model.Door, prov *model.IdentityProvider) []string {
	var out []string
	for _, p := range d.ExternalParties {
		if p.Subject != "" {
			out = append(out, "IAM member: "+p.Subject)
		}
	}
	if len(d.TrustActions) > 0 {
		out = append(out, "role: "+strings.Join(d.TrustActions, ", "))
	}
	if prov != nil {
		if prov.AttributeCondition == "" {
			out = append(out, "attributeCondition: (none)")
		} else {
			out = append(out, "attributeCondition: "+prov.AttributeCondition)
		}
		if len(prov.Audiences) == 0 {
			out = append(out, "allowedAudiences: (default - the provider's own resource name)")
		} else {
			out = append(out, "allowedAudiences: "+strings.Join(prov.Audiences, ", "))
		}
	}
	if len(out) == 0 {
		return doorEvidence(d)
	}
	return out
}

// gcpBindingFix renders the corrected member line. GCP has no trust-policy
// document to paste, so the fix is the gcloud command that rewrites the
// binding.
func gcpBindingFix(d *model.Door, p *model.ExternalParty, prov *model.IdentityProvider) string {
	pool := poolOf(prov)
	if pool == "" {
		pool = "projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL"
	}
	member := "principalSet://iam.googleapis.com/" + pool + "/attribute.repository/YOUR_ORG/YOUR_REPO"
	if p.Project != "" && !strings.ContainsAny(p.Project, "*?") {
		member = "principalSet://iam.googleapis.com/" + pool + "/attribute.repository/" + p.Project
	}

	return "gcloud iam service-accounts add-iam-policy-binding " + d.ResourceName + " \\\n" +
		"  --role=" + orDefault(firstOrEmpty(d.TrustActions), "roles/iam.workloadIdentityUser") + " \\\n" +
		"  --member='" + member + "'\n\n" +
		"# then remove the pool-wide member:\n" +
		"gcloud iam service-accounts remove-iam-policy-binding " + d.ResourceName + " \\\n" +
		"  --role=" + orDefault(firstOrEmpty(d.TrustActions), "roles/iam.workloadIdentityUser") + " \\\n" +
		"  --member='principalSet://iam.googleapis.com/" + pool + "/*'"
}

func poolOf(prov *model.IdentityProvider) string {
	if prov == nil {
		return ""
	}
	return prov.Pool
}

func shortPool(pool string) string {
	if i := strings.LastIndex(pool, "/"); i >= 0 && i+1 < len(pool) {
		return pool[i+1:]
	}
	if pool == "" {
		return "the pool"
	}
	return pool
}
