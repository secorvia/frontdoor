package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secorvia/frontdoor/internal/model"
)

func sample() *model.Result {
	res := &model.Result{
		Tool:        "frontdoor",
		Version:     "test",
		GeneratedAt: time.Date(2026, 9, 24, 9, 12, 44, 0, time.UTC),
		Accounts: []model.Account{
			{Provider: model.ProviderAWS, ID: "111122223333", Alias: "acme-prod", Scanned: true},
			{Provider: model.ProviderAWS, ID: "999988887777", InOrg: true},
		},
		Doors: []model.Door{
			{
				Provider: model.ProviderAWS, AccountID: "111122223333",
				ResourceARN:   "arn:aws:iam::111122223333:role/ci-deploy",
				ResourceName:  "ci-deploy",
				PrincipalType: model.PrincipalOIDC,
				Issuer:        "token.actions.githubusercontent.com",
				ExternalParties: []model.ExternalParty{
					{Kind: model.PartyGitHub, Display: "ANY GitHub Actions tenant", Scope: model.ScopeAnyone, Wildcard: true},
				},
				IsPrivileged:     true,
				PrivilegeReasons: []string{"grants iam:PassRole"},
			},
			{
				Provider: model.ProviderAWS, AccountID: "111122223333",
				ResourceARN:   "arn:aws:iam::111122223333:role/deploy-prod",
				ResourceName:  "deploy-prod",
				PrincipalType: model.PrincipalOIDC,
				Issuer:        "token.actions.githubusercontent.com",
				ExternalParties: []model.ExternalParty{
					{Kind: model.PartyGitHub, Display: "github.com/acme/api @ refs/heads/main", Scope: model.ScopeExact},
				},
			},
			{
				Provider: model.ProviderAWS, AccountID: "111122223333",
				ResourceARN:   "arn:aws:iam::111122223333:role/ec2",
				PrincipalType: model.PrincipalService,
				ExternalParties: []model.ExternalParty{
					{Kind: model.PartyAWSService, Display: "AWS service ec2.amazonaws.com"},
				},
			},
		},
		Findings: []model.Finding{
			{
				ID: "FD001", Severity: model.SeverityCritical,
				Title:         "ANY GitHub Actions tenant can assume role/ci-deploy",
				Provider:      model.ProviderAWS,
				AccountID:     "111122223333",
				ResourceARN:   "arn:aws:iam::111122223333:role/ci-deploy",
				ResourceName:  "ci-deploy",
				Issuer:        "token.actions.githubusercontent.com",
				ExternalParty: "ANY GitHub Actions tenant",
				WhatIsWrong:   "The trust policy places no condition on token.actions.githubusercontent.com:sub, so the subject claim is never checked.",
				AttackerCan:   "Anyone able to get a token from token.actions.githubusercontent.com can assume this role.",
				Evidence:      []string{"StringEquals token.actions.githubusercontent.com:aud = sts.amazonaws.com"},
				Fix: model.Fix{
					Summary:     "Pin the subject claim to the exact identity you intend to trust.",
					TrustPolicy: "\"Condition\": {\n  \"StringEquals\": {\n    \"x:sub\": \"repo:acme/api:ref:refs/heads/main\"\n  }\n}",
					Steps:       []string{"Confirm which repository is supposed to use this role."},
				},
				DocsURL: "https://www.secorvia.com/docs/frontdoor/FD001",
			},
			{
				ID: "FD013", Severity: model.SeverityHigh,
				Title:       "Cross-account trust to 999988887777 has no ExternalId",
				Provider:    model.ProviderAWS,
				AccountID:   "111122223333",
				ResourceARN: "arn:aws:iam::111122223333:role/partner",
				WhatIsWrong: "Account 999988887777 can assume this role knowing only its ARN.",
				AttackerCan: "Another customer of the same third party can ask it to assume your role ARN.",
				Fix:         model.Fix{Summary: "Require an external id."},
				DocsURL:     "https://www.secorvia.com/docs/frontdoor/FD013",
			},
			{
				ID: "FD021", Severity: model.SeverityMedium,
				Title:          "Stale external trust: role/legacy",
				Provider:       model.ProviderAWS,
				AccountID:      "111122223333",
				ResourceARN:    "arn:aws:iam::111122223333:role/legacy",
				WhatIsWrong:    "Never assumed.",
				AttackerCan:    "Use it unnoticed.",
				Fix:            model.Fix{Summary: "Remove it."},
				DocsURL:        "https://www.secorvia.com/docs/frontdoor/FD021",
				Suppressed:     true,
				SuppressReason: "retiring 2026-10-01, OPS-42",
			},
		},
		Unreadable: []model.Unreadable{
			{Operation: "organizations:ListAccounts", Code: "AccessDenied", Denied: true},
			{Operation: "iam:GetRole", Code: "Throttling", Denied: false},
		},
	}
	res.Counts = model.Tally(res.Findings)
	return res
}

func render(t *testing.T, res *model.Result, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, res, opts); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// --- summary -----------------------------------------------------------------

// The summary line is the sentence people quote. It must name the platform,
// not the rule id, and must not count service-principal trusts as doors.
func TestSummaryLine(t *testing.T) {
	got := SummaryLine(sample())
	want := "2 external identities can enter your cloud. 1 accepts ANY GitHub repository."
	if got != want {
		t.Errorf("SummaryLine()\n got: %q\nwant: %q", got, want)
	}
}

func TestSummaryLineVariants(t *testing.T) {
	empty := &model.Result{Accounts: []model.Account{{ID: "1", Scanned: true}}}
	if got := SummaryLine(empty); got != "No external identity can enter your cloud." {
		t.Errorf("empty account: %q", got)
	}

	// Several platforms wide open at once: naming one would be misleading.
	mixed := &model.Result{
		Accounts: []model.Account{{ID: "1", Scanned: true}},
		Doors: []model.Door{
			{PrincipalType: model.PrincipalOIDC, ExternalParties: []model.ExternalParty{
				{Kind: model.PartyGitHub, Scope: model.ScopeAnyone},
			}},
			{PrincipalType: model.PrincipalOIDC, ExternalParties: []model.ExternalParty{
				{Kind: model.PartyGitLab, Scope: model.ScopeAnyone},
			}},
		},
	}
	if got := SummaryLine(mixed); !strings.Contains(got, "2 accept ANY caller from their issuer") {
		t.Errorf("mixed platforms: %q", got)
	}

	// Exactly one identity: singular throughout.
	one := &model.Result{
		Accounts: []model.Account{{ID: "1", Scanned: true}},
		Doors: []model.Door{
			{PrincipalType: model.PrincipalOIDC, ExternalParties: []model.ExternalParty{
				{Kind: model.PartyGitHub, Scope: model.ScopeExact},
			}},
		},
	}
	if got := SummaryLine(one); got != "1 external identity can enter your cloud." {
		t.Errorf("singular: %q", got)
	}
}

func TestCountsLineOmitsEmptySeverities(t *testing.T) {
	got := CountsLine(sample())
	if !strings.Contains(got, "1 critical") || !strings.Contains(got, "1 high") {
		t.Errorf("CountsLine = %q", got)
	}
	if strings.Contains(got, "0 low") || strings.Contains(got, "0 info") {
		t.Errorf("CountsLine includes empty severities: %q", got)
	}
	if !strings.Contains(got, "(1 suppressed)") {
		t.Errorf("CountsLine does not report suppressions: %q", got)
	}
}

func TestExitCode(t *testing.T) {
	res := sample()
	if got := ExitCode(res, model.SeverityCritical); got != 1 {
		t.Errorf("fail-on critical = %d, want 1", got)
	}
	if got := ExitCode(res, model.SeverityHigh); got != 1 {
		t.Errorf("fail-on high = %d, want 1", got)
	}

	// The only medium is suppressed, so raising the bar to medium on a result
	// with no live medium must not trip.
	onlySuppressed := &model.Result{Findings: []model.Finding{
		{ID: "FD021", Severity: model.SeverityMedium, Suppressed: true},
	}}
	if got := ExitCode(onlySuppressed, model.SeverityMedium); got != 0 {
		t.Errorf("a suppressed finding tripped the exit code: %d", got)
	}
}

// --- terminal ----------------------------------------------------------------

func TestTerminalNoColorWhenDisabled(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatTerminal, Color: false, Width: 96})
	if strings.Contains(out, "\x1b[") {
		t.Error("terminal output contains ANSI escapes with Color: false")
	}
}

func TestTerminalColorWhenEnabled(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatTerminal, Color: true, Width: 96})
	if !strings.Contains(out, "\x1b[") {
		t.Error("terminal output has no ANSI escapes with Color: true")
	}
}

func TestTerminalContent(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatTerminal, Color: false, Width: 96, IgnorePath: ".frontdoorignore"})

	for _, want := range []string{
		"WHO CAN GET IN",
		"ANY GitHub Actions tenant",
		"role/ci-deploy",
		"privileged",
		"CRITICAL",
		"FD001",
		"arn:aws:iam::111122223333:role/ci-deploy",
		"repo:acme/api:ref:refs/heads/main", // the pasteable fix survives wrapping
		"https://www.secorvia.com/docs/frontdoor/FD001",
		"SCAN GAPS",
		"organizations:ListAccounts",
		"2 external identities can enter your cloud.",
		"Suppressions from .frontdoorignore",
		"acme-prod (111122223333)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output is missing %q", want)
		}
	}

	// A denied call is a gap; a throttle is not.
	if strings.Contains(out, "iam:GetRole") {
		t.Error("a non-denial was listed as a scan gap")
	}
	// Suppressed findings are not rendered as live findings.
	if strings.Contains(out, "Stale external trust") {
		t.Error("a suppressed finding was rendered in the report body")
	}
}

// Long lines have to wrap, but an ARN or a URL must never be broken across
// lines - someone is going to copy it.
func TestTerminalWrappingKeepsIdentifiersIntact(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatTerminal, Color: false, Width: 60})
	if !strings.Contains(out, "arn:aws:iam::111122223333:role/ci-deploy") {
		t.Error("an ARN was broken by wrapping at width 60")
	}
	if !strings.Contains(out, "https://www.secorvia.com/docs/frontdoor/FD001") {
		t.Error("a URL was broken by wrapping at width 60")
	}
}

func TestTerminalCleanAccount(t *testing.T) {
	clean := &model.Result{
		Tool:     "frontdoor",
		Accounts: []model.Account{{ID: "111122223333", Scanned: true}},
	}
	out := render(t, clean, Options{Format: FormatTerminal, Color: false, Width: 96})
	if !strings.Contains(out, "No external identity can enter your cloud.") {
		t.Errorf("clean account report:\n%s", out)
	}
	if strings.Contains(out, "CRITICAL") || strings.Contains(out, "SCAN GAPS") {
		t.Error("clean report contains sections it has no content for")
	}
}

func TestQuietPrintsOnlySummary(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatTerminal, Quiet: true})
	if strings.Contains(out, "FD001") || strings.Contains(out, "WHO CAN GET IN") {
		t.Errorf("--quiet printed the full report:\n%s", out)
	}
	if !strings.Contains(out, "external identities can enter") {
		t.Errorf("--quiet printed no summary:\n%s", out)
	}
}

func TestUseColorRespectsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if UseColor(ColorAlways, os.Stdout) {
		t.Error("NO_COLOR was set and --color always still enabled colour")
	}
}

func TestUseColorNeverAndNonTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")

	if UseColor(ColorNever, os.Stdout) {
		t.Error("--color never enabled colour")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if UseColor(ColorAuto, f) {
		t.Error("colour was enabled for a file, which is not a terminal")
	}
	if !UseColor(ColorAlways, f) {
		t.Error("--color always did not force colour for a file")
	}
}

// --- sarif -------------------------------------------------------------------

func TestSARIFShape(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatSARIF})

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Name       string `json:"name"`
						HelpURI    string `json:"helpUri"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]

	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3 (suppressed findings are reported as suppressed, not dropped)", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want one per distinct rule id", len(run.Tool.Driver.Rules))
	}

	for _, r := range run.Results {
		// GitHub silently drops a result with no location.
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("%s has no location URI", r.RuleID)
		}
		// And dedupes alerts across runs on the fingerprint.
		if r.PartialFingerprints["frontdoor/v1"] == "" {
			t.Errorf("%s has no partial fingerprint", r.RuleID)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("%s ruleIndex %d is out of range", r.RuleID, r.RuleIndex)
		}
		if got := run.Tool.Driver.Rules[r.RuleIndex].ID; got != r.RuleID {
			t.Errorf("ruleIndex points at %q, not %q", got, r.RuleID)
		}
	}

	levels := map[string]string{}
	for _, r := range run.Results {
		levels[r.RuleID] = r.Level
	}
	for id, want := range map[string]string{"FD001": "error", "FD013": "error", "FD021": "warning"} {
		if levels[id] != want {
			t.Errorf("%s level = %q, want %q", id, levels[id], want)
		}
	}

	// Without security-severity GitHub shows every alert as the same severity.
	for _, r := range run.Tool.Driver.Rules {
		if r.Properties.SecuritySeverity == "" {
			t.Errorf("rule %s has no security-severity", r.ID)
		}
		if r.HelpURI == "" {
			t.Errorf("rule %s has no helpUri", r.ID)
		}
		if strings.Contains(r.Name, " ") {
			t.Errorf("rule %s name %q contains spaces; it must be an identifier", r.ID, r.Name)
		}
	}

	for _, r := range run.Results {
		if r.RuleID != "FD021" {
			continue
		}
		if len(r.Suppressions) != 1 {
			t.Fatalf("suppressed finding has %d suppressions, want 1", len(r.Suppressions))
		}
		if r.Suppressions[0].Justification != "retiring 2026-10-01, OPS-42" {
			t.Errorf("justification = %q", r.Suppressions[0].Justification)
		}
	}
}

// The fingerprint has to be stable across runs or GitHub closes yesterday's
// alerts and opens identical new ones every night.
func TestSARIFFingerprintIsStable(t *testing.T) {
	a := render(t, sample(), Options{Format: FormatSARIF})

	later := sample()
	later.GeneratedAt = later.GeneratedAt.Add(24 * time.Hour)
	b := render(t, later, Options{Format: FormatSARIF})

	extract := func(s string) []string {
		var out []string
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "frontdoor/v1") {
				out = append(out, strings.TrimSpace(line))
			}
		}
		return out
	}
	fa, fb := extract(a), extract(b)
	if len(fa) == 0 {
		t.Fatal("no fingerprints emitted")
	}
	if strings.Join(fa, "|") != strings.Join(fb, "|") {
		t.Errorf("fingerprints changed between runs:\n%v\n%v", fa, fb)
	}
}

func TestARNToURI(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::111122223333:role/ci-deploy":           "aws/111122223333/iam/role/ci-deploy",
		"arn:aws:iam::111122223333:oidc-provider/gitlab.com": "aws/111122223333/iam/oidc-provider/gitlab.com",
		"AKIAEXAMPLE": "cloud/AKIAEXAMPLE",
		"":            "cloud/unknown",
	}
	for in, want := range cases {
		if got := arnToURI(in); got != want {
			t.Errorf("arnToURI(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- mermaid -----------------------------------------------------------------

func TestMermaid(t *testing.T) {
	out := render(t, sample(), Options{Format: FormatMermaid})

	if !strings.HasPrefix(out, "```mermaid\ngraph LR\n") {
		t.Errorf("mermaid output does not open a fenced graph:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "```") {
		t.Error("mermaid block is not closed")
	}
	for _, want := range []string{
		`"ANY GitHub Actions tenant"`,
		`"role/ci-deploy"`,
		"classDef critical",
		"-->",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mermaid output is missing %q", want)
		}
	}
	// Service trusts are not doors from outside and do not belong on the graph.
	if strings.Contains(out, "ec2.amazonaws.com") {
		t.Error("a service-principal trust was drawn on the trust graph")
	}
}

// Mermaid breaks on unescaped brackets and quotes, and subject claims are full
// of both.
func TestMermaidEscaping(t *testing.T) {
	res := &model.Result{
		Doors: []model.Door{{
			PrincipalType: model.PrincipalOIDC,
			ResourceARN:   "arn:aws:iam::1:role/x",
			ExternalParties: []model.ExternalParty{
				{Kind: model.PartyBitbucket, Display: `bitbucket repository {11111111-2222}["quoted"]`},
			},
		}},
	}
	out := render(t, res, Options{Format: FormatMermaid})

	label := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "bitbucket") {
			label = line
		}
	}
	if label == "" {
		t.Fatalf("label not found in:\n%s", out)
	}
	for _, bad := range []string{"{", "}", `["quoted"]`} {
		if strings.Contains(label, bad) {
			t.Errorf("label still contains %q, which breaks the mermaid parser: %s", bad, label)
		}
	}
}

// The same party reaching two doors must be one node, not two, and must take
// the worse of the two classes.
func TestMermaidNodeReuseAndWorstClass(t *testing.T) {
	res := &model.Result{
		Doors: []model.Door{
			{PrincipalType: model.PrincipalOIDC, ResourceARN: "arn:aws:iam::1:role/clean",
				ExternalParties: []model.ExternalParty{{Kind: model.PartyGitHub, Display: "github.com/acme/api"}}},
			{PrincipalType: model.PrincipalOIDC, ResourceARN: "arn:aws:iam::1:role/bad",
				ExternalParties: []model.ExternalParty{{Kind: model.PartyGitHub, Display: "github.com/acme/api"}}},
		},
		Findings: []model.Finding{
			{ID: "FD001", Severity: model.SeverityCritical, ResourceARN: "arn:aws:iam::1:role/bad"},
		},
	}
	out := render(t, res, Options{Format: FormatMermaid})

	if ids := nodeIDsFor(out, "github.com/acme/api"); len(ids) != 1 {
		t.Errorf("the same party got %d node ids %v, want 1:\n%s", len(ids), ids, out)
	}
	if !strings.Contains(out, "class N0 critical;") {
		t.Errorf("a party reaching a critical door was not classed critical:\n%s", out)
	}
	if strings.Contains(out, "class N0 ok;") {
		t.Errorf("the weaker class overwrote the critical one:\n%s", out)
	}
}

// A chain drawn with a separate id space for sources and targets would show
// the middle service account twice and the path would not connect. This is the
// test that keeps the graph a graph.
func TestMermaidChainIsOneConnectedPath(t *testing.T) {
	res := &model.Result{
		Doors: []model.Door{{
			Provider: model.ProviderGCP, PrincipalType: model.PrincipalOIDC,
			ResourceARN:  "projects/acme/serviceAccounts/ci@acme.iam.gserviceaccount.com",
			ResourceName: "ci@acme.iam.gserviceaccount.com",
			ExternalParties: []model.ExternalParty{
				{Kind: model.PartyGitHub, Display: "ANY GitHub Actions tenant", Scope: model.ScopeAnyone},
			},
		}},
		Chains: []model.Chain{{
			Provider: model.ProviderGCP,
			Entry:    model.ExternalParty{Display: "ANY GitHub Actions tenant", Scope: model.ScopeAnyone},
			Hops: []model.Hop{
				{Kind: model.EdgeFederation, From: "ANY GitHub Actions tenant", To: "ci@acme.iam.gserviceaccount.com"},
				{Kind: model.EdgeImpersonation, From: "ci@acme.iam.gserviceaccount.com",
					To: "deploy@acme.iam.gserviceaccount.com", Via: "roles/iam.serviceAccountTokenCreator",
					ToPrivileged: true, ToReasons: []string{"holds roles/owner"}},
			},
			Terminal:           "deploy@acme.iam.gserviceaccount.com",
			TerminalPrivileged: true,
		}},
	}
	out := render(t, res, Options{Format: FormatMermaid})

	// The middle account is a door target and a chain source. One node.
	mid := nodeIDsFor(out, "ci@acme")
	if len(mid) != 1 {
		t.Fatalf("the middle of the chain got %d node ids %v, so the path is drawn broken:\n%s",
			len(mid), mid, out)
	}
	// And an edge must leave that same node, whatever arrow style it uses.
	if !edgeLeaves(out, mid[0]) {
		t.Errorf("no edge leaves the middle node %s:\n%s", mid[0], out)
	}
	if !strings.Contains(out, `"deploy@acme"`) {
		t.Errorf("the chain terminal is not on the graph:\n%s", out)
	}
	// The terminal is privileged, so it must be visually marked as such.
	term := nodeIDsFor(out, "deploy@acme")
	if len(term) != 1 || !strings.Contains(out, "class "+term[0]+" privileged;") {
		t.Errorf("the privileged terminal is not classed privileged:\n%s", out)
	}
}

// A chain that ends somewhere harmless would double the size of the graph for
// no benefit, so it is left out.
func TestMermaidSkipsHarmlessChains(t *testing.T) {
	res := &model.Result{
		Doors: []model.Door{{
			PrincipalType: model.PrincipalOIDC, ResourceARN: "arn:aws:iam::1:role/ci",
			ExternalParties: []model.ExternalParty{{Kind: model.PartyGitHub, Display: "repo"}},
		}},
		Chains: []model.Chain{{
			Entry: model.ExternalParty{Display: "repo"},
			Hops: []model.Hop{
				{Kind: model.EdgeImpersonation, From: "a@x.iam.gserviceaccount.com", To: "b@x.iam.gserviceaccount.com"},
			},
			Terminal: "b@x.iam.gserviceaccount.com", TerminalPrivileged: false,
		}},
	}
	out := render(t, res, Options{Format: FormatMermaid})
	if strings.Contains(out, "b@x") {
		t.Errorf("a chain ending somewhere harmless was drawn:\n%s", out)
	}
}

// nodeIDsFor returns every mermaid node id that carries the given label.
func nodeIDsFor(mermaid, label string) []string {
	var found []string
	seen := map[string]bool{}
	needle := `["` + label + `"]`
	for _, line := range strings.Split(mermaid, "\n") {
		rest := line
		for {
			i := strings.Index(rest, needle)
			if i < 0 {
				break
			}
			start := i
			for start > 0 && rest[start-1] != ' ' && rest[start-1] != '>' {
				start--
			}
			if id := strings.TrimSpace(rest[start:i]); id != "" && !seen[id] {
				seen[id] = true
				found = append(found, id)
			}
			rest = rest[i+len(needle):]
		}
	}
	return found
}

func TestMermaidEmpty(t *testing.T) {
	out := render(t, &model.Result{}, Options{Format: FormatMermaid})
	if !strings.Contains(out, "No external identity can enter this account") {
		t.Errorf("empty graph:\n%s", out)
	}
}

// --- format parsing ----------------------------------------------------------

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"":         FormatTerminal,
		"terminal": FormatTerminal,
		"TEXT":     FormatTerminal,
		"json":     FormatJSON,
		"sarif":    FormatSARIF,
		"mermaid":  FormatMermaid,
	} {
		got, ok := ParseFormat(in)
		if !ok || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	if _, ok := ParseFormat("yaml"); ok {
		t.Error("ParseFormat accepted an unsupported format")
	}
}

// edgeLeaves reports whether any edge in the diagram starts at the given node,
// regardless of which arrow style or label it uses.
func edgeLeaves(mermaid, id string) bool {
	for _, line := range strings.Split(mermaid, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, id+"[") {
			continue
		}
		if strings.Contains(trimmed, "-->") || strings.Contains(trimmed, "==>") {
			return true
		}
	}
	return false
}

// A cross-cloud hop is the edge nothing else draws, so it must be visually
// distinct and say which way it crosses.
func TestMermaidMarksTheCloudBoundary(t *testing.T) {
	res := &model.Result{
		Doors: []model.Door{{
			Provider: model.ProviderAWS, PrincipalType: model.PrincipalOIDC,
			ResourceARN: "arn:aws:iam::1:role/ci", ResourceName: "ci", NodeID: "arn:aws:iam::1:role/ci",
			ExternalParties: []model.ExternalParty{
				{Kind: model.PartyGitHub, Display: "github.com/acme/api", Scope: model.ScopeExact},
			},
		}},
		Chains: []model.Chain{{
			Provider: model.ProviderAWS,
			Entry:    model.ExternalParty{Display: "github.com/acme/api", Scope: model.ScopeExact},
			Hops: []model.Hop{
				{Kind: model.EdgeFederation, From: "github.com/acme/api", To: "arn:aws:iam::1:role/ci",
					Provider: model.ProviderAWS},
				{Kind: model.EdgeCrossCloud, From: "arn:aws:iam::1:role/ci",
					To: "pipeline@acme.iam.gserviceaccount.com", Via: "roles/iam.workloadIdentityUser",
					FromProvider: model.ProviderAWS, Provider: model.ProviderGCP,
					ToSensitivity: model.SensitivityData, ToReach: []string{"BigQuery datasets"}},
			},
			Terminal:            "pipeline@acme.iam.gserviceaccount.com",
			TerminalSensitivity: model.SensitivityData,
			TerminalReach:       []string{"BigQuery datasets"},
			Clouds:              []model.Provider{model.ProviderAWS, model.ProviderGCP},
		}},
	}
	out := render(t, res, Options{Format: FormatMermaid})

	if !strings.Contains(out, "==>") {
		t.Errorf("the cross-cloud hop is drawn like any other edge:\n%s", out)
	}
	if !strings.Contains(out, "|AWS to GCP|") {
		t.Errorf("the edge does not say which way it crosses:\n%s", out)
	}
	if !strings.Contains(out, `"pipeline@acme"`) {
		t.Errorf("the other cloud is not on the graph:\n%s", out)
	}
}
