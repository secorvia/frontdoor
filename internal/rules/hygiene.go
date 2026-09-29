package rules

import (
	"sort"
	"strconv"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// hygieneRules cover the state of the federation itself rather than any one
// trust policy: FD020, FD021 and FD022.
func (c *evalContext) hygieneRules() {
	c.fd020()
	c.fd021Providers()
	c.fd021Roles()
	c.fd022()
}

// FD020 - static keys alongside federation. The whole point of federation is
// that there is no long-lived credential to steal; a forgotten access key
// undoes it, and nobody is watching that door.
func (c *evalContext) fd020() {
	now := c.opts.now()
	maxAge := c.opts.maxKeyAgeDays()

	for _, k := range c.res.AccessKeys {
		if !strings.EqualFold(k.Status, "Active") {
			continue
		}
		if c.externalDoorCount(k.AccountID) == 0 {
			continue // no federation in this account; this is a different tool's finding
		}

		age := k.AgeDays(now)
		lastUsed := daysSince(k.LastUsed, now)

		// A fresh key in daily use is how a lot of legitimate tooling works.
		// Flagging it would bury the keys that actually matter.
		if age >= 0 && age < maxAge && lastUsed >= 0 && lastUsed < c.opts.staleDays() {
			continue
		}

		var why, evidence []string
		if age >= 0 {
			evidence = append(evidence, "created "+strconv.Itoa(age)+" days ago")
			if age >= maxAge {
				why = append(why, "it is "+strconv.Itoa(age)+" days old and has never been rotated")
			}
		}
		switch {
		case k.LastUsed == nil && k.Provider == model.ProviderGCP:
			// GCP does not expose last-used for service account keys. "Never
			// used" and "we cannot see" are different claims, and only one of
			// them is true here.
			evidence = append(evidence, "last use not reported by GCP")
		case k.LastUsed == nil && k.Provider == model.ProviderAzure:
			evidence = append(evidence, "last use not reported by Entra ID")
		case k.LastUsed == nil:
			why = append(why, "it has never been used")
			evidence = append(evidence, "never used")
		case lastUsed >= c.opts.staleDays():
			why = append(why, "it has not been used for "+strconv.Itoa(lastUsed)+" days")
			evidence = append(evidence, "last used "+strconv.Itoa(lastUsed)+" days ago via "+orDefault(k.LastService, "an unknown service"))
		default:
			evidence = append(evidence, "last used "+strconv.Itoa(lastUsed)+" days ago via "+orDefault(k.LastService, "an unknown service"))
		}
		if len(why) == 0 {
			// Nothing concrete to say about this key - an unknown creation
			// date is not a reason to flag it.
			continue
		}

		f := model.Finding{
			ID:           "FD020",
			Severity:     model.SeverityMedium,
			Title:        "Long-lived access key on a federated account: " + k.UserName,
			Provider:     providerOr(k.Provider),
			AccountID:    k.AccountID,
			ResourceARN:  orDefault(k.UserARN, k.AccessKeyID),
			ResourceName: k.UserName,
			WhatIsWrong: "This " + accountWord(k.Provider) + " uses federation, but " +
				identityWord(k.Provider) + " " + k.UserName +
				" still has an active key and " + joinAnd(why) + ".",
			AttackerCan: "Use the key from anywhere, indefinitely, with none of the short lifetime, audience " +
				"binding or revocability that makes federation worth adopting.",
			Evidence: append([]string{"access key " + k.AccessKeyID}, evidence...),
			Fix: model.Fix{
				Summary: "Move this workload onto the federation you already have, then delete the key.",
				Steps:   keyFixSteps(k.Provider),
			},
		}
		c.add(f)
	}
}

// FD021a - a provider no role references. It is a door frame with no door: it
// costs nothing to remove and every day it stays is a day someone can write a
// trust policy against it without adding anything that looks new.
func (c *evalContext) fd021Providers() {
	for _, p := range c.res.IdentityProviders {
		if len(p.ReferencedBy) > 0 {
			continue
		}
		name := p.URL
		if name == "" {
			name = orDefault(p.EntityID, p.ARN)
		}

		f := model.Finding{
			ID:           "FD021",
			Severity:     model.SeverityMedium,
			Title:        "Unused identity provider: " + name,
			Provider:     providerOr(p.Provider),
			AccountID:    p.AccountID,
			ResourceARN:  p.ARN,
			ResourceName: name,
			Issuer:       name,
			WhatIsWrong:  "This identity provider is registered but nothing references it.",
			AttackerCan: "Anyone who can write an IAM policy can point a role or service account at this " +
				"provider without creating anything that looks new, and reviewers tend to assume a " +
				"registered provider is in use.",
			Evidence: []string{"referenced by 0 roles or service accounts"},
			Fix: model.Fix{
				Summary: "Delete the provider if the integration is gone.",
				Steps:   providerFixSteps(p.Provider),
			},
		}
		c.add(f)
	}
}

// FD021b - a door nobody has walked through. Unused access is the access that
// gets forgotten, and forgotten access is what incident reports are made of.
func (c *evalContext) fd021Roles() {
	now := c.opts.now()
	stale := c.opts.staleDays()

	seen := map[string]bool{}
	for i := range c.res.Doors {
		d := &c.res.Doors[i]
		if !d.IsExternal() || seen[d.ResourceARN] {
			continue
		}
		age := daysSince(d.CreatedAt, now)
		used := daysSince(d.LastUsed, now)

		var wrong, evidence string
		switch {
		case d.LastUsed == nil:
			// A role created last week that has not been used yet is not
			// stale, it is new. And when the creation date is unknown (age is
			// -1) we know nothing at all, so we say nothing - "never used"
			// with no idea how long is not evidence of anything.
			if age < stale {
				continue
			}
			wrong = "This role has an external trust but has never been assumed"
			if age >= 0 {
				wrong += ", and it was created " + strconv.Itoa(age) + " days ago"
			}
			evidence = "never used"
		case used >= stale:
			wrong = "This role has an external trust and has not been assumed for " + strconv.Itoa(used) + " days"
			evidence = "last used " + strconv.Itoa(used) + " days ago"
		default:
			continue
		}
		seen[d.ResourceARN] = true

		f := fromDoor(d, "FD021", model.SeverityMedium, "Stale external trust: "+short(d.ResourceARN))
		f.WhatIsWrong = wrong + "."
		f.AttackerCan = "Use it without anyone noticing a change in a pattern, because there is no pattern - " +
			"and unused roles are rarely on anyone's review list."
		f.Evidence = []string{evidence}
		if d.LastUsed == nil && daysSince(d.LastUsed, now) < 0 {
			f.Evidence = append(f.Evidence,
				"note: AWS only began recording role last-used data in 2019, and it is region-scoped")
		}
		f.Fix = model.Fix{
			Summary: "Remove the trust, or the whole role, if the integration is finished.",
			Steps: []string{
				"Check CloudTrail for AssumeRole events on this role across all regions before deleting.",
				"If the role is still wanted but the external trust is not, delete just that statement.",
			},
		}
		c.add(f)
	}
}

// wellKnownThumbprintExempt lists issuers for which AWS validates the TLS
// chain against its own trust store and ignores the thumbprint entirely. A
// stale thumbprint on these is untidy, not dangerous, and calling it a medium
// would be wrong.
var wellKnownThumbprintExempt = map[string]bool{
	"token.actions.githubusercontent.com": true,
	"gitlab.com":                          true,
	"accounts.google.com":                 true,
	"oauth2.googleapis.com":               true,
	"app.terraform.io":                    true,
	"agent.buildkite.com":                 true,
}

func thumbprintExempt(issuer string) bool {
	n := model.NormalizeIssuer(issuer)
	if wellKnownThumbprintExempt[n] {
		return true
	}
	// CircleCI, Vercel and Bitbucket namespace the issuer with a tenant id.
	for _, prefix := range []string{"oidc.circleci.com", "oidc.vercel.com", "api.bitbucket.org"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// FD022 - thumbprint missing, or not matching the certificate the issuer is
// actually serving.
func (c *evalContext) fd022() {
	for _, p := range c.res.IdentityProviders {
		// Thumbprints are an AWS concept. GCP validates its providers against
		// the public CA set and has no thumbprint field at all, so a GCP
		// provider with none is correct, not misconfigured. Listing the
		// providers that opt out - rather than demanding an explicit "aws" -
		// keeps a hand-assembled result behaving the same as a collected one.
		if p.Type != model.PrincipalOIDC {
			continue
		}
		if p.Provider == model.ProviderGCP || p.Provider == model.ProviderAzure {
			continue
		}
		exempt := thumbprintExempt(p.URL)

		if len(p.Thumbprints) == 0 {
			sev := model.SeverityMedium
			note := ""
			if exempt {
				sev = model.SeverityLow
				note = " AWS validates this issuer against its own trust store, so the missing thumbprint " +
					"is not currently exploitable - but that behaviour is AWS's to change, not yours."
			}
			f := model.Finding{
				ID:           "FD022",
				Severity:     sev,
				Title:        "No thumbprint on OIDC provider " + p.URL,
				Provider:     model.ProviderAWS,
				AccountID:    p.AccountID,
				ResourceARN:  p.ARN,
				ResourceName: p.URL,
				Issuer:       p.URL,
				WhatIsWrong:  "The provider has no CA thumbprint registered." + note,
				AttackerCan: "If AWS falls back to thumbprint verification for this issuer, an attacker who can " +
					"intercept TLS to it could present their own certificate and mint tokens you would accept.",
				Evidence: []string{"thumbprint_list is empty"},
				Fix: model.Fix{
					Summary: "Register the thumbprint of the issuer's CA certificate.",
					Steps: []string{
						"aws iam update-open-id-connect-provider-thumbprint --open-id-connect-provider-arn " + p.ARN,
						"Take the thumbprint from the issuer's own published value, not from whatever your " +
							"laptop happens to negotiate.",
					},
				},
			}
			c.add(f)
			continue
		}

		// Live comparison only happens when --resolve was passed. Without it
		// the tool makes no claim about the current certificate.
		resolved, ok := c.opts.Resolved[p.ARN]
		if !ok || resolved.Err != "" || len(resolved.Thumbprints) == 0 {
			continue
		}
		if thumbprintsIntersect(p.Thumbprints, resolved.Thumbprints) {
			continue
		}

		sev := model.SeverityMedium
		note := ""
		if exempt {
			sev = model.SeverityLow
			note = " AWS validates this well-known issuer against its own trust store, so this mismatch is " +
				"unlikely to break anything today."
		}
		f := model.Finding{
			ID:           "FD022",
			Severity:     sev,
			Title:        "Thumbprint does not match the certificate " + p.URL + " is serving",
			Provider:     model.ProviderAWS,
			AccountID:    p.AccountID,
			ResourceARN:  p.ARN,
			ResourceName: p.URL,
			Issuer:       p.URL,
			WhatIsWrong: "None of the registered thumbprints match the CA chain the issuer currently presents." +
				note,
			AttackerCan: "Nothing directly - but the registered value is stale, so if AWS does fall back to it " +
				"the provider will either stop working or trust the wrong certificate.",
			Evidence: []string{
				"registered: " + strings.Join(p.Thumbprints, ", "),
				"observed:   " + strings.Join(resolved.Thumbprints, ", "),
			},
			Fix: model.Fix{
				Summary: "Update the thumbprint to the issuer's current CA.",
				Steps: []string{
					"aws iam update-open-id-connect-provider-thumbprint --open-id-connect-provider-arn " + p.ARN +
						" --thumbprint-list " + firstOr(resolved.Thumbprints, "NEW_THUMBPRINT"),
					"Confirm the value against the issuer's documentation before applying it.",
				},
			},
		}
		c.add(f)
	}
}

func thumbprintsIntersect(a, b []string) bool {
	set := map[string]bool{}
	for _, s := range a {
		set[strings.ToLower(strings.ReplaceAll(s, ":", ""))] = true
	}
	for _, s := range b {
		if set[strings.ToLower(strings.ReplaceAll(s, ":", ""))] {
			return true
		}
	}
	return false
}

func firstOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	return sorted[0]
}

// --- provider wording --------------------------------------------------------
//
// AWS and GCP call the same things by different names. Printing "IAM user" for
// a GCP service account would make a reader doubt everything else in the
// report, so the wording follows the provider.

func providerOr(p model.Provider) model.Provider {
	if p == "" {
		return model.ProviderAWS
	}
	return p
}

func accountWord(p model.Provider) string {
	if p == model.ProviderGCP {
		return "project"
	}
	return "account"
}

func identityWord(p model.Provider) string {
	if p == model.ProviderGCP {
		return "service account"
	}
	return "IAM user"
}

func keyFixSteps(p model.Provider) []string {
	if p == model.ProviderGCP {
		return []string{
			"Check Cloud Audit Logs for what still authenticates with this key. If nothing does, delete it.",
			"If something does, move it onto workload identity federation, which is already set up in this project.",
			"Disable the key first and wait a cycle before deleting, so a surprise consumer fails loudly.",
			"Consider the constraints/iam.disableServiceAccountKeyCreation org policy so the next one is not created.",
		}
	}
	return []string{
		"Check CloudTrail for what still uses this key. If nothing does, delete it.",
		"If something does, give it a role and let it assume that role through the existing OIDC provider.",
		"Deactivate the key first and wait a cycle before deleting, so a surprise consumer fails loudly.",
	}
}

func providerFixSteps(p model.Provider) []string {
	if p == model.ProviderGCP {
		return []string{
			"Confirm no service account in any project in the organization binds to this pool - " +
				"frontdoor only sees the projects it was pointed at.",
			"Delete the provider, then the pool, with gcloud iam workload-identity-pools providers delete.",
			"A deleted pool is recoverable for 30 days, so this is a safe thing to try.",
		}
	}
	return []string{
		"Confirm no role in any account in the organization uses it - frontdoor only sees this account.",
		"Delete it with iam:DeleteOpenIDConnectProvider or iam:DeleteSAMLProvider.",
		"Re-registering it later takes a minute; leaving it costs you a blind spot.",
	}
}
