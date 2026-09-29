package awscollect

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

const selfAccount = "111122223333"

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

func doorsFromFixture(t *testing.T, name string, mutate ...func(*trustInput)) []model.Door {
	t.Helper()
	in := trustInput{
		AccountID: selfAccount,
		RoleARN:   "arn:aws:iam::" + selfAccount + ":role/ci-deploy",
		RoleName:  "ci-deploy",
		Document:  loadFixture(t, name),
	}
	for _, m := range mutate {
		m(&in)
	}
	doors, _, err := doorsFromTrustPolicy(in)
	if err != nil {
		t.Fatalf("doorsFromTrustPolicy(%s): %v", name, err)
	}
	return doors
}

func onlyDoor(t *testing.T, doors []model.Door) model.Door {
	t.Helper()
	if len(doors) != 1 {
		t.Fatalf("want exactly 1 door, got %d", len(doors))
	}
	return doors[0]
}

func onlyParty(t *testing.T, d model.Door) model.ExternalParty {
	t.Helper()
	if len(d.ExternalParties) != 1 {
		t.Fatalf("want exactly 1 external party, got %d", len(d.ExternalParties))
	}
	return d.ExternalParties[0]
}

// A trust policy with an aud condition but no sub condition admits any
// repository on GitHub. This is the headline case the tool exists for, so it
// must not be mistaken for a narrow trust.
func TestWildcardSubject_NoSubCondition(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "github-wildcard-sub.json"))

	if d.PrincipalType != model.PrincipalOIDC {
		t.Errorf("PrincipalType = %q, want oidc", d.PrincipalType)
	}
	if d.Issuer != "token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q", d.Issuer)
	}
	p := onlyParty(t, d)
	if p.Scope != model.ScopeAnyone {
		t.Errorf("Scope = %q, want anyone", p.Scope)
	}
	if !p.Wildcard {
		t.Error("Wildcard = false, want true")
	}
	if !d.HasConditionKey("token.actions.githubusercontent.com:aud") {
		t.Error("aud condition was dropped")
	}
	if len(d.ConditionsForSuffix(":sub")) != 0 {
		t.Error("found a sub condition that the fixture does not have")
	}
}

// sub: "*" is the same door, written explicitly.
func TestWildcardSubject_StarSub(t *testing.T) {
	p := onlyParty(t, onlyDoor(t, doorsFromFixture(t, "github-star-sub.json")))
	if p.Scope != model.ScopeAnyone {
		t.Errorf("Scope = %q, want anyone", p.Scope)
	}
	if !p.Wildcard {
		t.Error("Wildcard = false, want true")
	}
}

func TestExactSubject(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "github-exact-sub.json"))
	p := onlyParty(t, d)

	if p.Kind != model.PartyGitHub {
		t.Errorf("Kind = %q, want github_actions", p.Kind)
	}
	if p.Org != "acme" || p.Project != "api" {
		t.Errorf("Org/Project = %q/%q, want acme/api", p.Org, p.Project)
	}
	if p.Ref != "refs/heads/main" {
		t.Errorf("Ref = %q", p.Ref)
	}
	if p.Scope != model.ScopeExact {
		t.Errorf("Scope = %q, want exact", p.Scope)
	}
	if p.Wildcard {
		t.Error("Wildcard = true on a literal subject")
	}
	if want := "github.com/acme/api @ refs/heads/main"; p.Display != want {
		t.Errorf("Display = %q, want %q", p.Display, want)
	}
}

// repo:acme/* lets every repository in the org in, including a brand new one
// any org member can create.
func TestOrgLevelSubject(t *testing.T) {
	p := onlyParty(t, onlyDoor(t, doorsFromFixture(t, "github-org-sub.json")))

	if p.Scope != model.ScopeOrg {
		t.Errorf("Scope = %q, want org", p.Scope)
	}
	if p.Org != "acme" {
		t.Errorf("Org = %q, want acme", p.Org)
	}
	if !p.Wildcard {
		t.Error("Wildcard = false on repo:acme/*")
	}
	if want := "ANY repository in github.com/acme"; p.Display != want {
		t.Errorf("Display = %q, want %q", p.Display, want)
	}
}

// Without an aud condition the role can be assumed with a token minted for a
// different audience. The sub may still be exact, so the parse must stay
// correct while the missing aud is visible to the rules.
func TestMissingAudience(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "github-missing-aud.json"))

	if d.HasConditionKey("token.actions.githubusercontent.com:aud") {
		t.Error("found an aud condition the fixture does not have")
	}
	if len(d.ConditionsForSuffix(":aud")) != 0 {
		t.Error("ConditionsForSuffix found a phantom aud condition")
	}
	p := onlyParty(t, d)
	if p.Scope != model.ScopeExact || p.Project != "api" {
		t.Errorf("subject parse broke: scope=%q project=%q", p.Scope, p.Project)
	}
}

func TestCrossAccount_WithExternalId(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "crossaccount-with-externalid.json"))

	if d.PrincipalType != model.PrincipalCrossAccount {
		t.Errorf("PrincipalType = %q, want cross_account", d.PrincipalType)
	}
	if !hasConditionKey(d.Conditions, "sts:ExternalId") {
		t.Error("sts:ExternalId condition was dropped")
	}
	p := onlyParty(t, d)
	if p.AccountID != "999988887777" {
		t.Errorf("AccountID = %q", p.AccountID)
	}
	if p.Vendor != "" {
		t.Errorf("Vendor = %q, want empty for an unknown account", p.Vendor)
	}
}

func TestCrossAccount_WithoutExternalId(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "crossaccount-no-externalid.json"))

	if hasConditionKey(d.Conditions, "sts:ExternalId") {
		t.Error("found an ExternalId condition the fixture does not have")
	}
	p := onlyParty(t, d)
	if p.AccountID != "999988887777" {
		t.Errorf("AccountID = %q, want the bare account id to parse", p.AccountID)
	}
	if p.Scope != model.ScopeAccount {
		t.Errorf("Scope = %q, want account", p.Scope)
	}
}

func TestCrossAccount_KnownVendorIsLabelled(t *testing.T) {
	p := onlyParty(t, onlyDoor(t, doorsFromFixture(t, "crossaccount-vendor.json")))

	if p.Vendor == "" {
		t.Fatal("Vendor is empty for a known vendor account id")
	}
	if p.VendorRef == "" {
		t.Error("VendorRef is empty; every vendor label must cite a source")
	}
}

// Same-account trust is not a door from outside and must not be reported.
// Service trusts are dropped unless asked for. Deny statements are ignored.
func TestMixedStatements(t *testing.T) {
	doors := doorsFromFixture(t, "mixed-statements.json")
	if len(doors) != 2 {
		t.Fatalf("want 2 doors (gitlab + okta), got %d", len(doors))
	}
	for _, d := range doors {
		if d.StatementSID != "TwoFederated" {
			t.Errorf("unexpected door from statement %q", d.StatementSID)
		}
	}

	var gitlab, okta *model.Door
	for i := range doors {
		switch doors[i].PrincipalType {
		case model.PrincipalOIDC:
			gitlab = &doors[i]
		case model.PrincipalSAML:
			okta = &doors[i]
		}
	}
	if gitlab == nil || okta == nil {
		t.Fatal("expected one OIDC and one SAML door")
	}

	gp := onlyParty(t, *gitlab)
	if gp.Kind != model.PartyGitLab || gp.Project != "acme/infra" || gp.Ref != "main" {
		t.Errorf("gitlab party = %+v", gp)
	}

	// The statement's only sub condition is gitlab.com:sub. That key is not in
	// the request context of a SAML assume, so StringEquals evaluates false
	// and the SAML path is broken rather than open. Reporting it as "any Okta
	// user" would be a false alarm; reporting it as exact would be worse.
	op := onlyParty(t, *okta)
	if op.Kind != model.PartySAMLIdP {
		t.Errorf("okta party kind = %q", op.Kind)
	}
	if op.Scope != model.ScopeUnknown {
		t.Errorf("okta scope = %q, want unknown for a foreign-namespace condition", op.Scope)
	}
	if op.Subject != "" {
		t.Errorf("okta subject = %q; the gitlab sub condition must not leak onto the SAML door", op.Subject)
	}
}

// A sub condition namespaced to another issuer does not constrain this door,
// and AWS will not evaluate it either. The two outcomes must be told apart.
func TestForeignNamespaceSubCondition(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow",
	  "Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringLike":{"gitlab.com:sub":"project_path:acme/infra:*"}}
	}]}`
	doors, _, err := doorsFromTrustPolicy(trustInput{AccountID: selfAccount, Document: doc})
	if err != nil {
		t.Fatal(err)
	}
	p := onlyParty(t, onlyDoor(t, doors))
	if p.Scope != model.ScopeUnknown {
		t.Errorf("Scope = %q, want unknown (broken door, not an open one)", p.Scope)
	}
	if p.Kind != model.PartyGitHub {
		t.Errorf("Kind = %q, want the provider's own platform", p.Kind)
	}
	if p.Wildcard {
		t.Error("Wildcard = true; this door admits nobody, it is not wide open")
	}
}

// IfExists passes vacuously when the key is absent, so a foreign-namespace
// condition using it leaves the door genuinely open.
func TestForeignNamespaceIfExistsIsOpen(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow",
	  "Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringLikeIfExists":{"gitlab.com:sub":"project_path:acme/infra:*"}}
	}]}`
	doors, _, err := doorsFromTrustPolicy(trustInput{AccountID: selfAccount, Document: doc})
	if err != nil {
		t.Fatal(err)
	}
	p := onlyParty(t, onlyDoor(t, doors))
	if p.Scope != model.ScopeAnyone {
		t.Errorf("Scope = %q, want anyone", p.Scope)
	}
}

func TestMixedStatements_IncludeService(t *testing.T) {
	doors := doorsFromFixture(t, "mixed-statements.json", func(in *trustInput) {
		in.IncludeService = true
	})
	services := 0
	for _, d := range doors {
		if d.PrincipalType == model.PrincipalService {
			services++
		}
	}
	if services != 2 {
		t.Errorf("want 2 service doors with --include-service, got %d", services)
	}
}

func TestPrincipalStar(t *testing.T) {
	p := onlyParty(t, onlyDoor(t, doorsFromFixture(t, "principal-star.json")))
	if p.Kind != model.PartyAnyone || p.Scope != model.ScopeAnyone {
		t.Errorf("party = %+v, want anyone", p)
	}
}

func TestGoogleFederation(t *testing.T) {
	d := onlyDoor(t, doorsFromFixture(t, "google-federation.json"))
	if d.Issuer != "accounts.google.com" {
		t.Errorf("Issuer = %q", d.Issuer)
	}
	p := onlyParty(t, d)
	if p.Kind != model.PartyGoogle {
		t.Errorf("Kind = %q, want google", p.Kind)
	}
	if p.Actor != "109876543210987654321" {
		t.Errorf("Actor = %q, want the GCP service account unique id", p.Actor)
	}
}

// IAM hands back trust policies URL-encoded from most APIs and raw from
// others. Both must parse to the same door.
func TestURLEncodedDocument(t *testing.T) {
	raw := loadFixture(t, "github-exact-sub.json")
	encoded := url.QueryEscape(raw)

	a := onlyDoor(t, doorsFromFixture(t, "github-exact-sub.json"))
	b, _, err := doorsFromTrustPolicy(trustInput{
		AccountID: selfAccount,
		RoleARN:   a.ResourceARN,
		RoleName:  a.ResourceName,
		Document:  encoded,
	})
	if err != nil {
		t.Fatalf("URL-encoded document failed to parse: %v", err)
	}
	if got := onlyParty(t, onlyDoor(t, b)).Display; got != onlyParty(t, a).Display {
		t.Errorf("encoded parse = %q, raw parse = %q", got, onlyParty(t, a).Display)
	}
}

// The provider index supplies audiences and thumbprints registered on the
// provider itself, which the trust policy does not repeat.
func TestProviderDetailsAttach(t *testing.T) {
	arn := "arn:aws:iam::" + selfAccount + ":oidc-provider/token.actions.githubusercontent.com"
	d := onlyDoor(t, doorsFromFixture(t, "github-exact-sub.json", func(in *trustInput) {
		in.Providers = map[string]*model.IdentityProvider{
			arn: {ARN: arn, Audiences: []string{"sts.amazonaws.com"}, Thumbprints: []string{"abc123"}},
		}
	}))
	if len(d.Audiences) != 1 || d.Audiences[0] != "sts.amazonaws.com" {
		t.Errorf("Audiences = %v", d.Audiences)
	}
	if len(d.Thumbprints) != 1 {
		t.Errorf("Thumbprints = %v", d.Thumbprints)
	}
}

func TestMalformedDocumentIsAnError(t *testing.T) {
	if _, _, err := doorsFromTrustPolicy(trustInput{
		AccountID: selfAccount, Document: "{not json",
	}); err == nil {
		t.Error("want an error for a malformed trust policy, got nil")
	}
}
