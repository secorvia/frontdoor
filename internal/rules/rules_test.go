package rules

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/secorvia/frontdoor/internal/model"
)

var testNow = time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)

const (
	selfAccount = "111122223333"
	roleARN     = "arn:aws:iam::111122223333:role/ci-deploy"
	ghIssuer    = "token.actions.githubusercontent.com"
)

func daysAgo(n int) *time.Time {
	t := testNow.AddDate(0, 0, -n)
	return &t
}

// githubDoor is a door with an exact, correctly-namespaced subject and
// audience - the shape a correct trust policy produces. Tests mutate it to
// introduce exactly one defect, so a rule that fires on the untouched door is
// a false positive by construction.
func githubDoor() model.Door {
	recent := testNow.AddDate(0, 0, -2)
	return model.Door{
		Provider:      model.ProviderAWS,
		AccountID:     selfAccount,
		ResourceARN:   roleARN,
		ResourceName:  "ci-deploy",
		PrincipalType: model.PrincipalOIDC,
		Issuer:        ghIssuer,
		Audiences:     []string{"sts.amazonaws.com"},
		LastUsed:      &recent,
		CreatedAt:     daysAgo(400),
		ExternalParties: []model.ExternalParty{{
			Kind: model.PartyGitHub, Scope: model.ScopeExact,
			Display: "github.com/acme/api @ refs/heads/main",
			Subject: "repo:acme/api:ref:refs/heads/main",
			Org:     "acme", Project: "api", Ref: "refs/heads/main",
		}},
		Conditions: []model.Condition{
			{Operator: "StringEquals", Key: ghIssuer + ":aud", Values: []string{"sts.amazonaws.com"}},
			{Operator: "StringEquals", Key: ghIssuer + ":sub", Values: []string{"repo:acme/api:ref:refs/heads/main"}},
		},
	}
}

func resultWith(doors ...model.Door) *model.Result {
	return &model.Result{
		Accounts: []model.Account{{Provider: model.ProviderAWS, ID: selfAccount, Scanned: true}},
		Doors:    doors,
	}
}

// run evaluates the rules and returns the unsuppressed findings by rule id.
func run(res *model.Result, mutate ...func(*Options)) map[string][]model.Finding {
	opts := Options{Now: testNow}
	for _, m := range mutate {
		m(&opts)
	}
	Run(res, opts)

	byID := map[string][]model.Finding{}
	for _, f := range res.Findings {
		if f.Suppressed {
			continue
		}
		byID[f.ID] = append(byID[f.ID], f)
	}
	return byID
}

func ids(byID map[string][]model.Finding) []string {
	out := make([]string, 0, len(byID))
	for id := range byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func only(t *testing.T, byID map[string][]model.Finding, id string) model.Finding {
	t.Helper()
	got := byID[id]
	if len(got) != 1 {
		t.Fatalf("want exactly 1 %s, got %d (all findings: %v)", id, len(got), ids(byID))
	}
	return got[0]
}

// A correctly written trust policy must produce nothing. This is the test that
// matters most: a scanner that flags a clean account is a scanner nobody runs
// twice.
func TestCleanDoorProducesNoFindings(t *testing.T) {
	byID := run(resultWith(githubDoor()))
	if len(byID) != 0 {
		t.Fatalf("clean door produced findings: %v", ids(byID))
	}
}

func TestFD001_NoSubjectCondition(t *testing.T) {
	d := githubDoor()
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Wildcard: true,
		Display: "ANY GitHub Actions tenant",
	}}
	d.Conditions = d.Conditions[:1] // keep aud, drop sub

	f := only(t, run(resultWith(d)), "FD001")
	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, ghIssuer+":sub") {
		t.Errorf("WhatIsWrong does not name the missing key: %q", f.WhatIsWrong)
	}
	if !strings.Contains(f.Fix.TrustPolicy, ghIssuer+":sub") {
		t.Errorf("Fix does not include a sub condition:\n%s", f.Fix.TrustPolicy)
	}
	if !strings.Contains(f.Fix.TrustPolicy, "sts.amazonaws.com") {
		t.Errorf("Fix does not pin the registered audience:\n%s", f.Fix.TrustPolicy)
	}
	if f.DocsURL != DocsBase+"FD001" {
		t.Errorf("DocsURL = %q", f.DocsURL)
	}
}

// A SAML trust with no subject condition admits every employee, which is bad,
// but it is not the open internet.
func TestFD001_SAMLIsHighNotCritical(t *testing.T) {
	d := githubDoor()
	d.PrincipalType = model.PrincipalSAML
	d.Issuer = "Okta"
	d.Conditions = nil
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartySAMLIdP, Scope: model.ScopeAnyone, Display: "ANY user of SAML IdP Okta",
	}}

	f := only(t, run(resultWith(d)), "FD001")
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high for a SAML door", f.Severity)
	}
}

// Principal:* held by aws:PrincipalOrgID is not the same as Principal:* held
// by nothing, and the severity must say so.
func TestFD001_PrincipalStarNarrowedByOrgID(t *testing.T) {
	wide := model.Door{
		Provider: model.ProviderAWS, AccountID: selfAccount, ResourceARN: roleARN,
		PrincipalType:   model.PrincipalCrossAccount,
		LastUsed:        daysAgo(1),
		ExternalParties: []model.ExternalParty{{Kind: model.PartyAnyone, Scope: model.ScopeAnyone}},
	}
	if f := only(t, run(resultWith(wide)), "FD001"); f.Severity != model.SeverityCritical {
		t.Errorf("bare Principal:* severity = %q, want critical", f.Severity)
	}

	narrowed := wide
	narrowed.Conditions = []model.Condition{
		{Operator: "StringEquals", Key: "aws:PrincipalOrgID", Values: []string{"o-abc123"}},
	}
	f := only(t, run(resultWith(narrowed)), "FD001")
	if f.Severity != model.SeverityHigh {
		t.Errorf("org-scoped Principal:* severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, "aws:PrincipalOrgID") {
		t.Errorf("WhatIsWrong does not credit the narrowing condition: %q", f.WhatIsWrong)
	}
}

func TestFD002_SeverityDependsOnSubject(t *testing.T) {
	// Exact subject, no aud: hardening, not an open door.
	pinned := githubDoor()
	pinned.Conditions = pinned.Conditions[1:] // drop aud, keep sub
	if f := only(t, run(resultWith(pinned)), "FD002"); f.Severity != model.SeverityMedium {
		t.Errorf("exact subject + no aud severity = %q, want medium", f.Severity)
	}

	// No subject and no aud: any token from the issuer works.
	open := githubDoor()
	open.Conditions = nil
	open.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Display: "ANY GitHub Actions tenant",
	}}
	byID := run(resultWith(open))
	if f := only(t, byID, "FD002"); f.Severity != model.SeverityCritical {
		t.Errorf("no subject + no aud severity = %q, want critical", f.Severity)
	}

	// Org-wide subject, no aud: the aud check was the only other barrier.
	broad := githubDoor()
	broad.Conditions = []model.Condition{
		{Operator: "StringLike", Key: ghIssuer + ":sub", Values: []string{"repo:acme/*"}},
	}
	broad.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeOrg, Org: "acme", Wildcard: true,
		Display: "ANY repository in github.com/acme", Subject: "repo:acme/*",
	}}
	if f := only(t, run(resultWith(broad)), "FD002"); f.Severity != model.SeverityHigh {
		t.Errorf("org subject + no aud severity = %q, want high", f.Severity)
	}
}

func TestFD002_NotFiredForSAML(t *testing.T) {
	d := githubDoor()
	d.PrincipalType = model.PrincipalSAML
	d.Issuer = "Okta"
	d.Conditions = []model.Condition{
		{Operator: "StringEquals", Key: "SAML:sub", Values: []string{"alice@acme.com"}},
	}
	d.ExternalParties = []model.ExternalParty{{Kind: model.PartySAMLIdP, Scope: model.ScopeExact}}

	if byID := run(resultWith(d)); len(byID["FD002"]) != 0 {
		t.Error("FD002 fired on a SAML door; AWS binds the SAML audience to the role ARN itself")
	}
}

func TestFD003_OnlyWhenPrivileged(t *testing.T) {
	open := githubDoor()
	open.Conditions = nil
	open.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Display: "ANY GitHub Actions tenant",
	}}

	if byID := run(resultWith(open)); len(byID["FD003"]) != 0 {
		t.Error("FD003 fired on an open door with no privileged grant")
	}

	priv := open
	priv.IsPrivileged = true
	priv.PrivilegeReasons = []string{"grants iam:PassRole: can pass any role to a service"}
	f := only(t, run(resultWith(priv)), "FD003")
	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.AttackerCan, "can pass any role") {
		t.Errorf("AttackerCan does not describe the escalation: %q", f.AttackerCan)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "iam:PassRole") {
		t.Errorf("Evidence does not name the action: %v", f.Evidence)
	}
}

func TestFD005_ForeignNamespace(t *testing.T) {
	d := githubDoor()
	d.Conditions = []model.Condition{
		{Operator: "StringLike", Key: "gitlab.com:sub", Values: []string{"project_path:acme/infra:*"}},
		{Operator: "StringEquals", Key: ghIssuer + ":aud", Values: []string{"sts.amazonaws.com"}},
	}
	d.ExternalParties = []model.ExternalParty{{Kind: model.PartyGitHub, Scope: model.ScopeUnknown}}

	byID := run(resultWith(d))
	f := only(t, byID, "FD005")
	if f.Severity != model.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, "gitlab.com:sub") {
		t.Errorf("WhatIsWrong does not name the wrong key: %q", f.WhatIsWrong)
	}
	if len(byID["FD001"]) != 0 {
		t.Error("FD001 fired on a broken door; it admits nobody, it is not wide open")
	}
}

func TestFD010_OrgWide(t *testing.T) {
	d := githubDoor()
	d.Conditions[1] = model.Condition{
		Operator: "StringLike", Key: ghIssuer + ":sub", Values: []string{"repo:acme/*"},
	}
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeOrg, Org: "acme", Wildcard: true,
		Display: "ANY repository in github.com/acme", Subject: "repo:acme/*",
	}}

	f := only(t, run(resultWith(d)), "FD010")
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Fix.TrustPolicy, "repo:acme/YOUR_REPO") {
		t.Errorf("Fix should keep the known org and ask for the repo:\n%s", f.Fix.TrustPolicy)
	}
}

func TestFD011_OnlyForRefCapablePlatforms(t *testing.T) {
	gh := githubDoor()
	gh.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeProject, Org: "acme", Project: "api",
		Display: "github.com/acme/api (any ref)", Subject: "repo:acme/api:*",
	}}
	if f := only(t, run(resultWith(gh)), "FD011"); f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}

	// Google federation has no branches. Reporting "no ref restriction" there
	// would be meaningless noise.
	g := githubDoor()
	g.Issuer = "accounts.google.com"
	g.Conditions = []model.Condition{
		{Operator: "StringEquals", Key: "accounts.google.com:aud", Values: []string{"123"}},
		{Operator: "StringEquals", Key: "accounts.google.com:sub", Values: []string{"123"}},
	}
	g.ExternalParties = []model.ExternalParty{{Kind: model.PartyGoogle, Scope: model.ScopeProject}}
	if byID := run(resultWith(g)); len(byID["FD011"]) != 0 {
		t.Error("FD011 fired on a platform with no ref concept")
	}
}

func TestFD012_PullRequest(t *testing.T) {
	d := githubDoor()
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeProject, Org: "acme", Project: "api",
		PullRequest: true, Display: "github.com/acme/api (pull_request)",
		Subject: "repo:acme/api:pull_request",
	}}

	f := only(t, run(resultWith(d)), "FD012")
	if !strings.Contains(f.WhatIsWrong, "pull_request_target") {
		t.Errorf("FD012 should explain the pull_request_target mechanism: %q", f.WhatIsWrong)
	}
}

func TestFD013_ExternalId(t *testing.T) {
	base := model.Door{
		Provider: model.ProviderAWS, AccountID: selfAccount, ResourceARN: roleARN,
		PrincipalType: model.PrincipalCrossAccount, LastUsed: daysAgo(1),
		ExternalParties: []model.ExternalParty{{
			Kind: model.PartyAWSAccount, AccountID: "999988887777", Scope: model.ScopeAccount,
			Display: "AWS account 999988887777",
		}},
	}

	// Without an ExternalId, and with the org readable, this is high.
	res := resultWith(base)
	res.Accounts = append(res.Accounts, model.Account{ID: "444455556666", InOrg: true})
	if f := only(t, run(res), "FD013"); f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}

	// With an ExternalId it does not fire at all.
	withID := base
	withID.Conditions = []model.Condition{
		{Operator: "StringEquals", Key: "sts:ExternalId", Values: []string{"acme-4f2c"}},
	}
	if byID := run(resultWith(withID)); len(byID["FD013"]) != 0 {
		t.Error("FD013 fired despite sts:ExternalId")
	}

	// A sibling account inside the org is not the confused-deputy scenario.
	sibling := base
	sibling.ExternalParties[0].AccountID = "444455556666"
	res2 := resultWith(sibling)
	res2.Accounts = append(res2.Accounts, model.Account{ID: "444455556666", InOrg: true})
	if byID := run(res2); len(byID["FD013"]) != 0 {
		t.Error("FD013 fired on a trust to our own organization")
	}
}

// When organizations:ListAccounts was denied the tool cannot prove the account
// is a stranger, and must not pretend otherwise.
func TestFD013_DowngradedWhenOrgUnknown(t *testing.T) {
	d := model.Door{
		Provider: model.ProviderAWS, AccountID: selfAccount, ResourceARN: roleARN,
		PrincipalType: model.PrincipalCrossAccount, LastUsed: daysAgo(1),
		ExternalParties: []model.ExternalParty{{
			Kind: model.PartyAWSAccount, AccountID: "999988887777", Scope: model.ScopeAccount,
		}},
	}
	f := only(t, run(resultWith(d)), "FD013")
	if f.Severity != model.SeverityMedium {
		t.Errorf("Severity = %q, want medium when the org layout is unreadable", f.Severity)
	}
	if !strings.Contains(f.WhatIsWrong, "could not be read") {
		t.Errorf("WhatIsWrong should admit the gap: %q", f.WhatIsWrong)
	}
}

func TestFD014_KnownVendorIsNotFlagged(t *testing.T) {
	d := model.Door{
		Provider: model.ProviderAWS, AccountID: selfAccount, ResourceARN: roleARN,
		PrincipalType: model.PrincipalCrossAccount, LastUsed: daysAgo(1),
		Conditions: []model.Condition{
			{Operator: "StringEquals", Key: "sts:ExternalId", Values: []string{"abc"}},
		},
		ExternalParties: []model.ExternalParty{{
			Kind: model.PartyAWSAccount, AccountID: "464622532012", Scope: model.ScopeAccount,
			Vendor: "Datadog", VendorRef: "https://docs.datadoghq.com/",
		}},
	}
	if byID := run(resultWith(d)); len(byID["FD014"]) != 0 {
		t.Error("FD014 fired on an account identified from the vendor's own published id")
	}

	// A name-based guess is not an identification and must still be flagged.
	guess := d
	guess.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyAWSAccount, AccountID: "999988887777", Scope: model.ScopeAccount,
		Vendor: "Wiz",
	}}
	f := only(t, run(resultWith(guess)), "FD014")
	if !strings.Contains(f.WhatIsWrong, "guess") {
		t.Errorf("WhatIsWrong should mark the vendor as a guess: %q", f.WhatIsWrong)
	}
}

func TestFD015_RepositoryOwnerAlone(t *testing.T) {
	d := githubDoor()
	d.Conditions = []model.Condition{
		{Operator: "StringEquals", Key: ghIssuer + ":aud", Values: []string{"sts.amazonaws.com"}},
		{Operator: "StringEquals", Key: ghIssuer + ":repository_owner", Values: []string{"acme"}},
	}
	d.ExternalParties = []model.ExternalParty{{Kind: model.PartyGitHub, Scope: model.ScopeUnknown}}
	if f := only(t, run(resultWith(d)), "FD015"); f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}

	// The numeric id cannot be re-registered, so it closes the typosquat.
	withID := d
	withID.Conditions = append(append([]model.Condition{}, d.Conditions...), model.Condition{
		Operator: "StringEquals", Key: ghIssuer + ":repository_owner_id", Values: []string{"12345"},
	})
	if byID := run(resultWith(withID)); len(byID["FD015"]) != 0 {
		t.Error("FD015 fired despite repository_owner_id being pinned")
	}

	// A pinned subject makes repository_owner redundant, not dangerous.
	withSub := githubDoor()
	withSub.Conditions = append(withSub.Conditions, model.Condition{
		Operator: "StringEquals", Key: ghIssuer + ":repository_owner", Values: []string{"acme"},
	})
	if byID := run(resultWith(withSub)); len(byID["FD015"]) != 0 {
		t.Error("FD015 fired on a door whose subject is already exact")
	}
}

func TestFD020_AccessKeys(t *testing.T) {
	res := resultWith(githubDoor())
	res.AccessKeys = []model.AccessKey{
		{AccountID: selfAccount, UserName: "old", AccessKeyID: "AKIA1", Status: "Active", CreatedAt: daysAgo(500), LastUsed: daysAgo(400)},
		{AccountID: selfAccount, UserName: "never", AccessKeyID: "AKIA2", Status: "Active", CreatedAt: daysAgo(200)},
		{AccountID: selfAccount, UserName: "fresh", AccessKeyID: "AKIA3", Status: "Active", CreatedAt: daysAgo(10), LastUsed: daysAgo(1)},
		{AccountID: selfAccount, UserName: "disabled", AccessKeyID: "AKIA4", Status: "Inactive", CreatedAt: daysAgo(500)},
	}

	got := run(res)["FD020"]
	if len(got) != 2 {
		t.Fatalf("want 2 FD020 findings (old, never), got %d", len(got))
	}
	names := []string{got[0].ResourceName, got[1].ResourceName}
	sort.Strings(names)
	if names[0] != "never" || names[1] != "old" {
		t.Errorf("flagged users = %v; a fresh, actively used key is not the problem", names)
	}
}

func TestFD020_NotFiredWithoutFederation(t *testing.T) {
	res := &model.Result{
		Accounts: []model.Account{{ID: selfAccount, Scanned: true}},
		AccessKeys: []model.AccessKey{
			{AccountID: selfAccount, UserName: "old", AccessKeyID: "AKIA1", Status: "Active", CreatedAt: daysAgo(500)},
		},
	}
	if byID := run(res); len(byID["FD020"]) != 0 {
		t.Error("FD020 fired on an account with no federation; that is a different tool's finding")
	}
}

func TestFD021_UnusedProviderAndStaleRole(t *testing.T) {
	res := resultWith(githubDoor())
	res.IdentityProviders = []model.IdentityProvider{
		{Provider: model.ProviderAWS, AccountID: selfAccount, Type: model.PrincipalOIDC,
			ARN: "arn:aws:iam::111122223333:oidc-provider/old.example.com", URL: "old.example.com",
			Thumbprints: []string{"abc"}, ReferencedBy: []string{}},
		{Provider: model.ProviderAWS, AccountID: selfAccount, Type: model.PrincipalOIDC,
			ARN: "arn:aws:iam::111122223333:oidc-provider/" + ghIssuer, URL: ghIssuer,
			Thumbprints: []string{"abc"}, ReferencedBy: []string{roleARN}},
	}

	got := run(res)["FD021"]
	if len(got) != 1 {
		t.Fatalf("want 1 FD021 (the unreferenced provider), got %d", len(got))
	}
	if !strings.Contains(got[0].Title, "old.example.com") {
		t.Errorf("wrong provider flagged: %q", got[0].Title)
	}

	// A role never assumed and old enough to have been.
	stale := githubDoor()
	stale.LastUsed = nil
	stale.CreatedAt = daysAgo(400)
	if len(run(resultWith(stale))["FD021"]) != 1 {
		t.Error("FD021 did not flag a role with an external trust that has never been used")
	}

	// A role created last week has not had a chance yet.
	fresh := githubDoor()
	fresh.LastUsed = nil
	fresh.CreatedAt = daysAgo(5)
	if len(run(resultWith(fresh))["FD021"]) != 0 {
		t.Error("FD021 flagged a role created 5 days ago as stale")
	}
}

func TestFD022_ThumbprintSeverityDependsOnIssuer(t *testing.T) {
	res := resultWith(githubDoor())
	res.IdentityProviders = []model.IdentityProvider{
		{Provider: model.ProviderAWS, AccountID: selfAccount, Type: model.PrincipalOIDC, ARN: "arn:a", URL: ghIssuer, ReferencedBy: []string{roleARN}},
		{Provider: model.ProviderAWS, AccountID: selfAccount, Type: model.PrincipalOIDC, ARN: "arn:b", URL: "id.example.internal", ReferencedBy: []string{roleARN}},
	}

	bySeverity := map[model.Severity]string{}
	for _, f := range run(res)["FD022"] {
		bySeverity[f.Severity] = f.ResourceName
	}
	if bySeverity[model.SeverityLow] != ghIssuer {
		t.Errorf("GitHub should be low - AWS validates it against its own trust store; got %v", bySeverity)
	}
	if bySeverity[model.SeverityMedium] != "id.example.internal" {
		t.Errorf("an unknown issuer with no thumbprint should be medium; got %v", bySeverity)
	}
}

func TestSuppression(t *testing.T) {
	d := githubDoor()
	d.Conditions = nil
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Display: "ANY GitHub Actions tenant",
	}}

	ignore, err := ParseIgnore(strings.NewReader(
		"# retiring this role\nFD001  " + roleARN + "   # tracked in OPS-42\n"))
	if err != nil {
		t.Fatal(err)
	}

	res := resultWith(d)
	Run(res, Options{Now: testNow, Ignore: ignore})

	var suppressed, live int
	for _, f := range res.Findings {
		if f.ID != "FD001" {
			continue
		}
		if f.Suppressed {
			suppressed++
			if f.SuppressReason != "tracked in OPS-42" {
				t.Errorf("SuppressReason = %q", f.SuppressReason)
			}
		} else {
			live++
		}
	}
	if suppressed != 1 || live != 0 {
		t.Errorf("suppressed=%d live=%d, want 1 and 0", suppressed, live)
	}
	if res.Counts.Suppressed != 1 {
		t.Errorf("Counts.Suppressed = %d, want 1", res.Counts.Suppressed)
	}
	// FD002 also fires on this door and is not suppressed, so the total is not zero.
	if res.Counts.Total == 0 {
		t.Error("suppressing FD001 should not have hidden the other findings")
	}
}

// Two runs over unchanged input must produce byte-identical order.
func TestFindingOrderIsDeterministic(t *testing.T) {
	build := func() *model.Result {
		open := githubDoor()
		open.Conditions = nil
		open.IsPrivileged = true
		open.PrivilegeReasons = []string{"grants *"}
		open.ExternalParties = []model.ExternalParty{{
			Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Display: "ANY GitHub Actions tenant",
		}}
		other := open
		other.ResourceARN = "arn:aws:iam::111122223333:role/aaa-first"
		return resultWith(open, other)
	}

	var first []string
	for i := 0; i < 5; i++ {
		res := build()
		Run(res, Options{Now: testNow})
		var order []string
		for _, f := range res.Findings {
			order = append(order, f.ID+" "+f.ResourceARN)
		}
		if i == 0 {
			first = order
			continue
		}
		if strings.Join(order, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d order differs:\n%v\n%v", i, first, order)
		}
	}
	if len(first) == 0 {
		t.Fatal("no findings produced")
	}

	// Severity leads the order, and within a severity the rule id does.
	res := build()
	Run(res, Options{Now: testNow})
	for i := 1; i < len(res.Findings); i++ {
		prev, cur := res.Findings[i-1], res.Findings[i]
		if cur.Severity.Rank() > prev.Severity.Rank() {
			t.Fatalf("finding %d (%s %s) outranks the one before it (%s %s)",
				i, cur.ID, cur.Severity, prev.ID, prev.Severity)
		}
	}
	if res.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("first finding severity = %q, want critical", res.Findings[0].Severity)
	}
}

func TestEveryFindingIsActionable(t *testing.T) {
	d := githubDoor()
	d.Conditions = nil
	d.IsPrivileged = true
	d.PrivilegeReasons = []string{"grants *"}
	d.ExternalParties = []model.ExternalParty{{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone, Display: "ANY GitHub Actions tenant",
	}}
	res := resultWith(d)
	res.AccessKeys = []model.AccessKey{
		{AccountID: selfAccount, UserName: "old", AccessKeyID: "AKIA1", Status: "Active", CreatedAt: daysAgo(500)},
	}
	res.IdentityProviders = []model.IdentityProvider{
		{Provider: model.ProviderAWS, AccountID: selfAccount, Type: model.PrincipalOIDC, ARN: "arn:x", URL: "id.example.internal"},
	}
	Run(res, Options{Now: testNow})

	if len(res.Findings) < 4 {
		t.Fatalf("expected several findings, got %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		switch {
		case f.ID == "":
			t.Error("finding has no rule id")
		case f.Title == "":
			t.Errorf("%s has no title", f.ID)
		case f.WhatIsWrong == "":
			t.Errorf("%s does not say what is wrong", f.ID)
		case f.AttackerCan == "":
			t.Errorf("%s does not say what an attacker could do", f.ID)
		case f.ResourceARN == "":
			t.Errorf("%s has no resource", f.ID)
		case f.Fix.Summary == "" && len(f.Fix.Steps) == 0:
			t.Errorf("%s has no fix", f.ID)
		case f.DocsURL == "":
			t.Errorf("%s has no docs link", f.ID)
		}
	}
}
