package rules

import (
	"strings"
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

// The chain tests use a shape that is common in real projects and looks
// innocent one hop at a time:
//
//	github.com/acme/api  ->  ci@        (looks fine, no privileges)
//	ci@                  ->  build@     (looks fine, no privileges)
//	build@               ->  deploy@    (project owner)
//
// Every tool that stops at the first hop says this account is clean.

func gcpDoor(party model.ExternalParty, sa string) model.Door {
	return model.Door{
		Provider:        model.ProviderGCP,
		AccountID:       "acme-prod",
		ResourceARN:     "projects/acme-prod/serviceAccounts/" + sa,
		ResourceName:    sa,
		NodeID:          sa,
		PrincipalType:   model.PrincipalOIDC,
		Issuer:          "https://token.actions.githubusercontent.com",
		TrustActions:    []string{"roles/iam.workloadIdentityUser"},
		ExternalParties: []model.ExternalParty{party},
	}
}

func impersonates(from, to string, privileged bool, reasons ...string) model.Hop {
	return model.Hop{
		Kind: model.EdgeImpersonation, From: from, To: to,
		Via: "roles/iam.serviceAccountTokenCreator", Provider: model.ProviderGCP,
		ToPrivileged: privileged, ToReasons: reasons,
	}
}

func chainFixture() (*model.Result, []model.Hop) {
	party := model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeExact,
		Display: "github.com/acme/api @ refs/heads/main",
	}
	res := &model.Result{
		Accounts: []model.Account{{Provider: model.ProviderGCP, ID: "acme-prod", Scanned: true}},
		Doors:    []model.Door{gcpDoor(party, "ci@acme-prod.iam.gserviceaccount.com")},
	}
	edges := []model.Hop{
		impersonates("ci@acme-prod.iam.gserviceaccount.com", "build@acme-prod.iam.gserviceaccount.com", false),
		impersonates("build@acme-prod.iam.gserviceaccount.com", "deploy@acme-prod.iam.gserviceaccount.com",
			true, "holds roles/owner: is project owner"),
	}
	return res, edges
}

func TestBuildChainsFollowsEveryHop(t *testing.T) {
	res, edges := chainFixture()
	chains := BuildChains(res, edges)

	if len(chains) != 2 {
		t.Fatalf("want 2 chains (to build@, to deploy@), got %d", len(chains))
	}

	var deep *model.Chain
	for i := range chains {
		if chains[i].Terminal == "deploy@acme-prod.iam.gserviceaccount.com" {
			deep = &chains[i]
		}
	}
	if deep == nil {
		t.Fatal("the chain that reaches the privileged account was not found")
	}

	if deep.Length() != 3 {
		t.Errorf("Length = %d, want 3 (federation + two impersonations)", deep.Length())
	}
	if !deep.TerminalPrivileged {
		t.Error("TerminalPrivileged = false on a chain ending at project owner")
	}

	want := "github.com/acme/api @ refs/heads/main -> ci@acme-prod.iam.gserviceaccount.com -> " +
		"build@acme-prod.iam.gserviceaccount.com -> deploy@acme-prod.iam.gserviceaccount.com"
	if got := deep.Path(); got != want {
		t.Errorf("Path()\n got: %s\nwant: %s", got, want)
	}
}

// A chain that loops back on itself must terminate rather than recurse until
// the stack gives out.
func TestBuildChainsHandlesCycles(t *testing.T) {
	party := model.ExternalParty{Kind: model.PartyGitHub, Scope: model.ScopeExact, Display: "repo"}
	res := &model.Result{Doors: []model.Door{gcpDoor(party, "a@x.iam.gserviceaccount.com")}}
	edges := []model.Hop{
		impersonates("a@x.iam.gserviceaccount.com", "b@x.iam.gserviceaccount.com", false),
		impersonates("b@x.iam.gserviceaccount.com", "c@x.iam.gserviceaccount.com", false),
		impersonates("c@x.iam.gserviceaccount.com", "a@x.iam.gserviceaccount.com", false),
		impersonates("c@x.iam.gserviceaccount.com", "b@x.iam.gserviceaccount.com", false),
	}

	done := make(chan []model.Chain, 1)
	go func() { done <- BuildChains(res, edges) }()

	chains := <-done
	if len(chains) == 0 {
		t.Fatal("no chains produced")
	}
	for _, c := range chains {
		seen := map[string]bool{}
		for _, h := range c.Hops {
			if seen[h.To] {
				t.Errorf("chain revisits %s: %s", h.To, c.Path())
			}
			seen[h.To] = true
		}
		if c.Length() > maxChainDepth {
			t.Errorf("chain longer than the depth cap: %s", c.Path())
		}
	}
}

// Ranking is by entry looseness times terminal sensitivity, never by length.
// A short chain into an owner account matters more than a long one into a log
// bucket, and the report has to say so.
func TestChainRiskIgnoresLength(t *testing.T) {
	short := model.Chain{
		Entry:              model.ExternalParty{Scope: model.ScopeAnyone},
		Hops:               []model.Hop{{}, {}},
		TerminalPrivileged: true,
	}
	long := model.Chain{
		Entry:              model.ExternalParty{Scope: model.ScopeExact},
		Hops:               []model.Hop{{}, {}, {}, {}, {}},
		TerminalPrivileged: false,
	}
	if short.Risk() <= long.Risk() {
		t.Errorf("short open chain risk %d should beat long pinned chain risk %d",
			short.Risk(), long.Risk())
	}
}

func TestFD030(t *testing.T) {
	res, edges := chainFixture()
	Run(res, Options{Now: testNow, ImpersonationEdges: edges})

	var fd030 []model.Finding
	for _, f := range res.Findings {
		if f.ID == "FD030" {
			fd030 = append(fd030, f)
		}
	}
	if len(fd030) != 1 {
		t.Fatalf("want 1 FD030 (only the chain ending privileged), got %d", len(fd030))
	}

	f := fd030[0]
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high for a pinned entry point", f.Severity)
	}
	if !strings.Contains(f.Title, "3 hops") {
		t.Errorf("Title does not say how far it goes: %q", f.Title)
	}

	// The full path is the finding. Reporting only the first hop is the bug
	// this rule exists to avoid.
	evidence := strings.Join(f.Evidence, " | ")
	for _, hop := range []string{"ci@", "build@", "deploy@"} {
		if !strings.Contains(evidence, hop) {
			t.Errorf("evidence omits %s, so the chain is not fully reported: %s", hop, evidence)
		}
	}
	if !strings.Contains(strings.Join(f.Fix.Steps, " "), "roles/iam.serviceAccountTokenCreator") {
		t.Errorf("the fix does not name a binding to remove: %v", f.Fix.Steps)
	}
}

// A wide-open entry point turns the same chain into a critical.
func TestFD030CriticalWhenEntryIsOpen(t *testing.T) {
	res, edges := chainFixture()
	res.Doors[0].ExternalParties[0] = model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeAnyone,
		Display: "ANY GitHub Actions tenant", Wildcard: true,
	}
	Run(res, Options{Now: testNow, ImpersonationEdges: edges})

	for _, f := range res.Findings {
		if f.ID != "FD030" {
			continue
		}
		if f.Severity != model.SeverityCritical {
			t.Errorf("Severity = %q, want critical when anyone can enter", f.Severity)
		}
		if !strings.Contains(f.Fix.Steps[0], "admits anyone") {
			t.Errorf("the fix should point at the weakest link first: %q", f.Fix.Steps[0])
		}
		return
	}
	t.Fatal("FD030 did not fire")
}

// With no impersonation edges there is no graph, and the rule must stay quiet
// rather than report every door as a one-hop chain.
func TestFD030QuietWithoutEdges(t *testing.T) {
	res, _ := chainFixture()
	Run(res, Options{Now: testNow})

	if len(res.Chains) != 0 {
		t.Errorf("chains were built with no edges: %d", len(res.Chains))
	}
	for _, f := range res.Findings {
		if f.ID == "FD030" {
			t.Error("FD030 fired with no impersonation edges")
		}
	}
}
