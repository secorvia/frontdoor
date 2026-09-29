package awscollect

import (
	"strings"
	"testing"
	"time"

	"github.com/secorvia/frontdoor/internal/model"
	"github.com/secorvia/frontdoor/internal/output"
	"github.com/secorvia/frontdoor/internal/rules"
)

// The collector and the rule engine are separate packages on purpose, but the
// thing the user runs is the whole pipeline. These tests drive a real trust
// policy through parsing, detection and output, with no AWS and no network.

var e2eNow = time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)

func scanFixture(t *testing.T, name string, mutate ...func(*trustInput)) *model.Result {
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
		t.Fatalf("parse %s: %v", name, err)
	}

	res := &model.Result{
		Accounts: []model.Account{{Provider: model.ProviderAWS, ID: selfAccount, Scanned: true}},
		Doors:    doors,
	}
	rules.Run(res, rules.Options{Now: e2eNow})
	return res
}

func ruleIDs(res *model.Result) []string {
	var out []string
	for _, f := range res.Findings {
		if !f.Suppressed {
			out = append(out, f.ID)
		}
	}
	return out
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// The headline case, end to end: a trust policy with an audience check and no
// subject check must come out the other side as a critical finding whose fix
// is pasteable.
func TestE2E_WildcardSubjectIsCritical(t *testing.T) {
	res := scanFixture(t, "github-wildcard-sub.json")
	ids := ruleIDs(res)

	if !has(ids, "FD001") {
		t.Fatalf("FD001 did not fire; findings = %v", ids)
	}
	if res.Counts.Critical == 0 {
		t.Errorf("no critical findings; counts = %+v", res.Counts)
	}

	var fd001 model.Finding
	for _, f := range res.Findings {
		if f.ID == "FD001" {
			fd001 = f
		}
	}
	fix := fd001.Fix.TrustPolicy
	for _, want := range []string{
		"\"Condition\"", "StringEquals",
		"token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:sub",
		"repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main",
	} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix is missing %q:\n%s", want, fix)
		}
	}

	if head := output.Headline(res); head == "" {
		t.Error("no headline for a critical finding")
	}
	if code := output.ExitCode(res, model.SeverityCritical); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

// A correctly written policy must produce nothing at all.
func TestE2E_ExactSubjectIsClean(t *testing.T) {
	res := scanFixture(t, "github-exact-sub.json")
	if len(res.Findings) != 0 {
		t.Fatalf("a correct trust policy produced findings: %v", ruleIDs(res))
	}
	if code := output.ExitCode(res, model.SeverityCritical); code != 0 {
		t.Errorf("ExitCode = %d, want 0", code)
	}
	if output.Headline(res) != "" {
		t.Error("clean scan produced a headline")
	}
}

func TestE2E_OrgWideSubject(t *testing.T) {
	ids := ruleIDs(scanFixture(t, "github-org-sub.json"))
	if !has(ids, "FD010") {
		t.Errorf("FD010 did not fire on repo:acme/*; findings = %v", ids)
	}
	if has(ids, "FD001") {
		t.Errorf("FD001 fired on an org-scoped subject; that is FD010's job: %v", ids)
	}
}

// Missing aud with an exact subject is a medium, and must not be dressed up.
func TestE2E_MissingAudienceWithExactSubject(t *testing.T) {
	res := scanFixture(t, "github-missing-aud.json")
	ids := ruleIDs(res)
	if !has(ids, "FD002") {
		t.Fatalf("FD002 did not fire; findings = %v", ids)
	}
	if res.Counts.Critical != 0 {
		t.Errorf("counts = %+v; an exact subject with no aud is not a critical", res.Counts)
	}
	if code := output.ExitCode(res, model.SeverityCritical); code != 0 {
		t.Errorf("ExitCode = %d; --fail-on critical should not trip on a medium", code)
	}
	if code := output.ExitCode(res, model.SeverityMedium); code != 1 {
		t.Errorf("ExitCode at --fail-on medium = %d, want 1", code)
	}
}

func TestE2E_CrossAccountExternalId(t *testing.T) {
	without := ruleIDs(scanFixture(t, "crossaccount-no-externalid.json"))
	if !has(without, "FD013") {
		t.Errorf("FD013 did not fire without an ExternalId: %v", without)
	}

	with := ruleIDs(scanFixture(t, "crossaccount-with-externalid.json"))
	if has(with, "FD013") {
		t.Errorf("FD013 fired despite sts:ExternalId: %v", with)
	}
	if !has(with, "FD014") {
		t.Errorf("FD014 should still flag an unrecognised account: %v", with)
	}
}

func TestE2E_KnownVendorIsNotAStranger(t *testing.T) {
	ids := ruleIDs(scanFixture(t, "crossaccount-vendor.json"))
	if has(ids, "FD014") {
		t.Errorf("FD014 fired on Datadog's published account id: %v", ids)
	}
}

func TestE2E_PrincipalStar(t *testing.T) {
	res := scanFixture(t, "principal-star.json")
	ids := ruleIDs(res)
	if !has(ids, "FD001") {
		t.Fatalf("FD001 did not fire on Principal:*; findings = %v", ids)
	}
	if res.Counts.Critical == 0 {
		t.Error("Principal:* with no conditions is not being reported as critical")
	}
}

// The whole pipeline must survive a round trip through JSON, because that is
// how anyone consumes it.
func TestE2E_FindingsSurviveJSON(t *testing.T) {
	res := scanFixture(t, "github-wildcard-sub.json")

	var buf strings.Builder
	if err := output.JSON(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, key := range []string{
		`"findings"`, `"counts"`, `"what_is_wrong"`,
		`"what_an_attacker_could_do"`, `"trust_policy"`, `"docs_url"`,
	} {
		if !strings.Contains(out, key) {
			t.Errorf("JSON is missing %s", key)
		}
	}
	if !strings.Contains(out, "secorvia.com/docs/frontdoor/FD001") {
		t.Error("findings do not link to the rule documentation")
	}
}
