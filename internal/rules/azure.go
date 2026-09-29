package rules

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// Azure's federated identity credential is the closest thing to an AWS trust
// policy in any of the three clouds: an issuer, a subject, and an audience,
// with no policy language in between. So most rules map straight across.
//
// The differences that matter are the ones where copying AWS would be wrong:
//
//   - Azure fixes the audience at api://AzureADTokenExchange. Anything else is
//     a token minted for a different relying party, so FD002 here is about a
//     WRONG audience rather than a missing one.
//   - A multi-tenant app registration is a door with no federated credential
//     at all: the signInAudience alone admits other tenants.
//   - Entra ID does not report last-use for app credentials, so FD020 must not
//     say "never used" about a secret it simply cannot see the usage of.

// azureAudience is the only audience Entra ID will accept on a federated
// credential, which makes any other value worth asking about.
const azureAudience = "api://AzureADTokenExchange"

func (c *evalContext) azureRules(d *model.Door) {
	for i := range d.ExternalParties {
		p := &d.ExternalParties[i]
		switch p.Scope {
		case model.ScopeAnyone:
			c.fd001Azure(d, p)
		case model.ScopeOrg:
			c.fd010(d, p)
		case model.ScopeProject:
			c.fd011(d, p)
		case model.ScopeUnknown:
			if p.Kind != model.PartyEntraGuest {
				c.fd005Azure(d, p)
			}
		}
		if p.PullRequest {
			c.fd012(d, p)
		}
	}

	c.fd002Azure(d)

	if d.IsPrivileged && c.doorIsOpen(d) {
		c.fd003(d, true, len(d.Audiences) > 0)
	}
}

// FD001 on Azure: nothing pins who may present a token.
func (c *evalContext) fd001Azure(d *model.Door, p *model.ExternalParty) {
	// A multi-tenant app is a different sentence from a wildcard subject, and
	// a different fix, so it gets its own wording rather than a generic one.
	if p.Kind == model.PartyEntraTenant {
		f := fromDoor(d, "FD001", model.SeverityCritical,
			"Any tenant can obtain a principal for "+d.ResourceName)
		f.ExternalParty = p.Display
		f.WhatIsWrong = "This app registration's signInAudience is " + p.Subject +
			", so an identity from outside this tenant can consent to it and act as it."
		f.AttackerCan = "Consent to the application from a tenant they control and receive a service " +
			"principal for it, with whatever this app has been granted."
		f.Evidence = doorEvidence(d)
		f.Fix = model.Fix{
			Summary: "Set signInAudience to AzureADMyOrg unless the app is genuinely a multi-tenant product.",
			Steps: []string{
				"az ad app update --id " + shortAppID(d.ResourceARN) + " --sign-in-audience AzureADMyOrg",
				"If it really is multi-tenant, the protection is not the audience - it is what the app " +
					"is allowed to do once consented. Review its API permissions and role assignments.",
			},
		}
		c.add(f)
		return
	}

	f := fromDoor(d, "FD001", model.SeverityCritical, p.Display+" can act as "+d.ResourceName)
	f.ExternalParty = p.Display
	f.WhatIsWrong = "The federated identity credential does not pin a subject, so any token " +
		model.NormalizeIssuer(d.Issuer) + " issues is accepted."
	f.AttackerCan = "Obtain a token from " + model.NormalizeIssuer(d.Issuer) +
		" - which on a public CI platform means anyone at all - and act as " + d.ResourceName + "."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary:     "Pin the subject to the exact identity you intend to trust.",
		TrustPolicy: azureFICFix(d, p),
		Steps: []string{
			"A federated credential matches on issuer + subject + audience. The subject is the only " +
				"one of the three that says WHO is calling.",
			"If several identities share this app, add one federated credential per subject rather " +
				"than widening a single one.",
		},
	}
	c.add(f)
}

// FD002 on Azure: the audience is fixed by the platform, so a different value
// is a token minted for something other than Entra ID.
func (c *evalContext) fd002Azure(d *model.Door) {
	if d.PrincipalType != model.PrincipalOIDC {
		return
	}

	var wrong []string
	for _, aud := range d.Audiences {
		if aud != azureAudience {
			wrong = append(wrong, aud)
		}
	}
	if len(d.Audiences) == 0 {
		wrong = append(wrong, "(none)")
	}
	if len(wrong) == 0 {
		return
	}

	sev := model.SeverityMedium
	if c.doorIsOpen(d) {
		sev = model.SeverityHigh
	}

	f := fromDoor(d, "FD002", sev, "Unexpected audience on "+d.ResourceName)
	f.WhatIsWrong = "The federated credential accepts the audience " + strings.Join(wrong, ", ") +
		" rather than " + azureAudience + ", which is the only value Entra ID issues tokens for. " +
		"A token minted for that audience by some other relying party is what gets presented here."
	f.AttackerCan = "Obtain a token issued for that audience - which may be far easier to come by " +
		"than one issued for Entra ID - and present it."
	f.Evidence = doorEvidence(d)
	f.Fix = model.Fix{
		Summary: "Set the audience to " + azureAudience + ".",
		Steps: []string{
			"Entra ID only ever issues exchange tokens for " + azureAudience + ".",
			"Any other value means the credential was configured for a different system, or copied " +
				"from one.",
		},
	}
	c.add(f)
}

// FD005 on Azure: a claims-matching expression we could not read. Saying
// nothing would leave the reader thinking it was checked; calling it open
// would be a guess.
func (c *evalContext) fd005Azure(d *model.Door, p *model.ExternalParty) {
	f := fromDoor(d, "FD005", model.SeverityLow,
		"Could not verify the claims expression on "+d.ResourceName)
	f.ExternalParty = p.Display
	f.WhatIsWrong = "This federated credential uses a claims-matching expression, and frontdoor " +
		"could not determine which subjects it admits. The expression is reproduced below verbatim."
	f.AttackerCan = "Unknown. This finding is a gap in the tool, not a proven weakness."
	f.Evidence = []string{"expression: " + p.Subject}
	f.Fix = model.Fix{
		Summary: "Confirm by hand that the expression pins the caller.",
		Steps: []string{
			"An expression that matches a wildcard subject admits everything that pattern covers.",
			"If the expression is correct, this is a false positive worth reporting: " +
				"https://github.com/secorvia/frontdoor/issues",
		},
	}
	c.add(f)
}

// azureFICFix renders the corrected credential as the az command that writes
// it, since Azure has no policy document to paste.
func azureFICFix(d *model.Door, p *model.ExternalParty) string {
	subject := "repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main"
	if p.Org != "" && p.Project != "" && !strings.ContainsAny(p.Org+p.Project, "*?") {
		subject = "repo:" + p.Org + "/" + p.Project + ":ref:refs/heads/main"
	}

	return "az ad app federated-credential create --id " + shortAppID(d.ResourceARN) + " --parameters '{\n" +
		"  \"name\": \"" + orDefault(p.Project, "deploy") + "-main\",\n" +
		"  \"issuer\": \"" + orDefault(d.Issuer, "https://token.actions.githubusercontent.com") + "\",\n" +
		"  \"subject\": \"" + subject + "\",\n" +
		"  \"audiences\": [\"" + azureAudience + "\"]\n" +
		"}'"
}

// shortAppID pulls the object id out of the synthetic resource path so the fix
// command is runnable as printed.
func shortAppID(resource string) string {
	if i := strings.LastIndex(resource, "/"); i >= 0 && i+1 < len(resource) {
		return resource[i+1:]
	}
	return "YOUR_APP_OBJECT_ID"
}
