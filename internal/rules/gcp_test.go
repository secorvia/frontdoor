package rules

import (
	"strings"
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

const (
	gcpPool     = "projects/123456789/locations/global/workloadIdentityPools/github"
	gcpProvider = gcpPool + "/providers/gh"
	gcpSA       = "ci@acme-prod.iam.gserviceaccount.com"
	gcpIssuer   = "https://token.actions.githubusercontent.com"
)

// gcpResult is a correctly configured GCP project: the binding names one
// repository and the provider has an attributeCondition. Tests break exactly
// one thing, so anything the untouched fixture reports is a false positive.
func gcpResult(party model.ExternalParty, attributeCondition string, audiences []string) *model.Result {
	return &model.Result{
		Accounts: []model.Account{{Provider: model.ProviderGCP, ID: "acme-prod", Scanned: true}},
		IdentityProviders: []model.IdentityProvider{{
			Provider: model.ProviderGCP, AccountID: "acme-prod",
			ARN: gcpProvider, Pool: gcpPool, Type: model.PrincipalOIDC,
			URL: gcpIssuer, AttributeCondition: attributeCondition, Audiences: audiences,
			ReferencedBy: []string{gcpSA},
		}},
		Doors: []model.Door{{
			Provider:        model.ProviderGCP,
			AccountID:       "acme-prod",
			ResourceARN:     "projects/acme-prod/serviceAccounts/" + gcpSA,
			ResourceName:    gcpSA,
			PrincipalType:   model.PrincipalOIDC,
			Issuer:          gcpIssuer,
			ProviderARN:     gcpProvider,
			Audiences:       audiences,
			TrustActions:    []string{"roles/iam.workloadIdentityUser"},
			ExternalParties: []model.ExternalParty{party},
		}},
	}
}

func exactGCPParty() model.ExternalParty {
	return model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeExact,
		Display: "github.com/acme/api @ refs/heads/main",
		Org:     "acme", Project: "api", Ref: "refs/heads/main",
		Subject: "principal://iam.googleapis.com/" + gcpPool + "/subject/repo:acme/api:ref:refs/heads/main",
	}
}

func TestGCPCleanProjectProducesNoFindings(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'", nil)
	byID := run(res)
	if len(byID) != 0 {
		t.Fatalf("a correctly configured GCP project produced findings: %v", ids(byID))
	}
}

// The GCP shape of an open door: the binding names the whole pool.
func TestGCPFD001WholePool(t *testing.T) {
	party := model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Wildcard: true,
		Display: "ANY GitHub Actions tenant (whole pool github)",
		Subject: "principalSet://iam.googleapis.com/" + gcpPool + "/*",
	}
	f := only(t, run(gcpResult(party, "", nil)), "FD001")

	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Provider != model.ProviderGCP {
		t.Errorf("Provider = %q, want gcp", f.Provider)
	}
	if !strings.Contains(f.WhatIsWrong, "attributeCondition") {
		t.Errorf("WhatIsWrong does not mention the missing attributeCondition: %q", f.WhatIsWrong)
	}
	if !strings.Contains(f.Fix.TrustPolicy, "gcloud iam service-accounts") {
		t.Errorf("the fix is not a runnable gcloud command:\n%s", f.Fix.TrustPolicy)
	}
	if !strings.Contains(f.Fix.TrustPolicy, "remove-iam-policy-binding") {
		t.Errorf("the fix does not remove the pool-wide member:\n%s", f.Fix.TrustPolicy)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "attributeCondition: (none)") {
		t.Errorf("evidence does not show the absent condition: %v", f.Evidence)
	}
}

// GCP's default audience is the provider's own resource name, which is
// specific and correct. Firing FD002 on an empty allowedAudiences would flag
// the right configuration on every provider in existence.
func TestGCPFD002NotFiredOnDefaultAudience(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'", nil)
	if byID := run(res); len(byID["FD002"]) != 0 {
		t.Error("FD002 fired on an empty allowedAudiences, which is GCP's secure default")
	}

	// An audience tied to this provider is equally fine.
	bound := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'",
		[]string{"//iam.googleapis.com/" + gcpProvider})
	if byID := run(bound); len(byID["FD002"]) != 0 {
		t.Error("FD002 fired on a provider-specific audience")
	}
}

func TestGCPFD002FiresOnSharedAudience(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'",
		[]string{"sts.amazonaws.com"})
	f := only(t, run(res), "FD002")

	if f.Severity != model.SeverityMedium {
		t.Errorf("Severity = %q, want medium with a pinned subject", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, "sts.amazonaws.com") {
		t.Errorf("WhatIsWrong does not name the shared audience: %q", f.WhatIsWrong)
	}
}

// An attributeCondition we cannot parse is reported as unverified, not as
// wide open. Guessing in either direction would be worse than saying so.
func TestGCPFD005UnreadableCondition(t *testing.T) {
	party := model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeUnknown,
		Display: "pool github where custom_thing = whatever",
	}
	res := gcpResult(party, "has(assertion.enterprise) && assertion.enterprise.size() > 0", nil)

	byID := run(res)
	f := only(t, byID, "FD005")
	if f.Severity != model.SeverityLow {
		t.Errorf("Severity = %q, want low - this is a gap in the tool, not a proven weakness", f.Severity)
	}
	if !strings.Contains(f.AttackerCan, "Unknown") {
		t.Errorf("AttackerCan should admit it does not know: %q", f.AttackerCan)
	}
	if len(byID["FD001"]) != 0 {
		t.Error("FD001 fired on a condition we could not read; that is a guess, not a finding")
	}
}

func TestGCPDomainWideBinding(t *testing.T) {
	party := model.ExternalParty{
		Kind: model.PartyGoogleDomain, Scope: model.ScopeDomain, Wildcard: true,
		Display: "EVERYONE in the domain acme.com", Org: "acme.com",
		Subject: "domain:acme.com",
	}
	f := only(t, run(gcpResult(party, "", nil)), "FD001")

	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high - a domain is too wide but is not the open internet", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, "acme.com") {
		t.Errorf("WhatIsWrong does not name the domain: %q", f.WhatIsWrong)
	}
}

func TestGCPOrgWideAttribute(t *testing.T) {
	party := model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeOrg, Org: "acme",
		Display: "ANY project owned by acme",
	}
	if f := only(t, run(gcpResult(party, "assertion.repository_owner == 'acme'", nil)), "FD010"); f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
}

// Thumbprints are an AWS concept. A GCP provider has none, and flagging that
// would put a medium on every project scanned.
func TestGCPProvidersAreNotFlaggedForThumbprints(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'", nil)
	if byID := run(res); len(byID["FD022"]) != 0 {
		t.Error("FD022 fired on a GCP provider, which has no thumbprint field at all")
	}
}

// GCP does not report last-used for service account keys, so an old key is
// flagged on its age and the finding must not claim it was never used.
func TestGCPServiceAccountKeys(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'", nil)
	res.AccessKeys = []model.AccessKey{{
		Provider: model.ProviderGCP, AccountID: "acme-prod",
		UserName: gcpSA, UserARN: "projects/acme-prod/serviceAccounts/" + gcpSA,
		AccessKeyID: "abc123", Status: "Active", CreatedAt: daysAgo(400),
	}}

	f := only(t, run(res), "FD020")
	if f.Provider != model.ProviderGCP {
		t.Errorf("Provider = %q, want gcp", f.Provider)
	}
	if strings.Contains(f.WhatIsWrong, "IAM user") {
		t.Errorf("a GCP finding calls the identity an IAM user: %q", f.WhatIsWrong)
	}
	if !strings.Contains(f.WhatIsWrong, "service account") {
		t.Errorf("WhatIsWrong does not use GCP wording: %q", f.WhatIsWrong)
	}
	if strings.Contains(strings.Join(f.Evidence, " "), "never used") {
		t.Errorf("the finding claims a key was never used when GCP does not report that: %v", f.Evidence)
	}
	if !strings.Contains(strings.Join(f.Fix.Steps, " "), "Cloud Audit Logs") {
		t.Errorf("the fix gives AWS advice for a GCP key: %v", f.Fix.Steps)
	}
}

func TestGCPUnusedPool(t *testing.T) {
	res := gcpResult(exactGCPParty(), "assertion.repository == 'acme/api'", nil)
	res.IdentityProviders = append(res.IdentityProviders, model.IdentityProvider{
		Provider: model.ProviderGCP, AccountID: "acme-prod",
		ARN: gcpPool + "/providers/unused", Pool: gcpPool, Type: model.PrincipalOIDC,
		URL: "https://gitlab.com", ReferencedBy: []string{},
	})

	f := only(t, run(res), "FD021")
	if f.Provider != model.ProviderGCP {
		t.Errorf("Provider = %q, want gcp", f.Provider)
	}
	if !strings.Contains(strings.Join(f.Fix.Steps, " "), "gcloud iam workload-identity-pools") {
		t.Errorf("the fix gives AWS advice for a GCP provider: %v", f.Fix.Steps)
	}
}
