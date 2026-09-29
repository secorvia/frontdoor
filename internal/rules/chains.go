package rules

import (
	"sort"
	"strconv"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// FD030 and FD031 are the findings that justify the whole project. A GitHub
// repository that can assume a build role looks fine on its own; the problem
// is that the build role federates into a GCP service account, and that
// account can read the warehouse. Every tool that reports the first hop and
// stops has told you the least interesting part.
//
// The graph is provider-neutral by construction. An edge is a pair of node ids
// and a kind; the builder never asks which cloud it is in except to say so in
// the output.

const (
	maxChainDepth = 6
	maxChains     = 200
)

// BuildChains walks every external entry point through the graph and records
// the paths. Chains of one hop are left out: a federated identity reaching one
// resource is an ordinary door, already covered by FD001 and FD003.
func BuildChains(res *model.Result, edges []model.Hop) []model.Chain {
	crossCloud, internal := DeriveCrossCloudEdges(res)
	edges = append(append([]model.Hop(nil), edges...), crossCloud...)
	if len(edges) == 0 {
		return nil
	}

	index := model.NewPrincipalIndex(res.Principals)

	adjacency := map[string][]model.Hop{}
	for _, e := range edges {
		enrichHop(&e, index)
		adjacency[e.From] = append(adjacency[e.From], e)
	}
	for k := range adjacency {
		sort.SliceStable(adjacency[k], func(i, j int) bool {
			return adjacency[k][i].To < adjacency[k][j].To
		})
	}

	var chains []model.Chain
	seen := map[string]bool{}

	for i := range res.Doors {
		d := &res.Doors[i]
		node := doorNode(d)
		if !d.IsExternal() || node == "" || len(adjacency[node]) == 0 {
			continue
		}

		for _, party := range d.ExternalParties {
			// A party that resolved to something we scanned is an internal
			// seam, not an entry point. Its own door already starts a chain.
			if internal[doorPartyKey(d, party)] {
				continue
			}

			entry := model.Hop{
				Kind:         model.EdgeFederation,
				From:         party.Display,
				To:           node,
				Via:          firstOrEmpty(d.TrustActions),
				Provider:     d.Provider,
				ToPrivileged: d.IsPrivileged,
				ToReasons:    d.PrivilegeReasons,
				Detail:       "can become " + model.ShortName(node),
			}
			enrichHop(&entry, index)

			walk(adjacency, d, party, []model.Hop{entry},
				map[string]bool{node: true}, &chains, seen)
		}
	}

	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Risk() != chains[j].Risk() {
			return chains[i].Risk() > chains[j].Risk()
		}
		if chains[i].Entry.Display != chains[j].Entry.Display {
			return chains[i].Entry.Display < chains[j].Entry.Display
		}
		return chains[i].Terminal < chains[j].Terminal
	})
	if len(chains) > maxChains {
		chains = chains[:maxChains]
	}
	return chains
}

// doorNode is how the graph addresses a door's resource. Collectors set
// NodeID; falling back to the ARN keeps a hand-built result working.
func doorNode(d *model.Door) string {
	switch {
	case d.NodeID != "":
		return d.NodeID
	case d.ResourceARN != "":
		return d.ResourceARN
	default:
		return d.ResourceName
	}
}

// enrichHop fills in what the far end of an edge is worth. The collectors know
// the permissions; only here do we know whether anything reaches them.
func enrichHop(h *model.Hop, index *model.PrincipalIndex) {
	p := index.Node(h.To)
	if p == nil {
		return
	}
	if p.Privileged {
		h.ToPrivileged = true
		if len(h.ToReasons) == 0 {
			h.ToReasons = p.Reasons
		}
	}
	if p.Sensitivity == "" {
		ClassifyPrincipal(p)
	}
	h.ToSensitivity = p.Sensitivity
	h.ToReach = p.Reach
	if h.Provider == "" {
		h.Provider = p.Provider
	}
}

// walk is a depth-first search that records a chain at every node beyond the
// first. Cycles are cut by the path set, not by a global visited set: the same
// identity can legitimately appear on two different paths.
func walk(adjacency map[string][]model.Hop, d *model.Door, party model.ExternalParty,
	path []model.Hop, onPath map[string]bool, out *[]model.Chain, seen map[string]bool) {

	if len(path) >= maxChainDepth || len(*out) >= maxChains {
		return
	}
	current := path[len(path)-1].To

	for _, edge := range adjacency[current] {
		if onPath[edge.To] {
			continue // a loop back to somewhere we already are adds nothing
		}

		next := append(append([]model.Hop(nil), path...), edge)
		chain := model.Chain{
			Provider:            d.Provider,
			Entry:               party,
			EntryVia:            d.ResourceARN,
			Hops:                next,
			Terminal:            edge.To,
			TerminalPrivileged:  edge.ToPrivileged,
			TerminalReasons:     edge.ToReasons,
			TerminalSensitivity: edge.ToSensitivity,
			TerminalReach:       edge.ToReach,
			Clouds:              cloudsOn(d.Provider, next),
			Weakest:             weakestLink(party),
		}

		key := party.Display + "\x00" + chain.Path()
		if !seen[key] {
			seen[key] = true
			*out = append(*out, chain)
		}

		onPath[edge.To] = true
		walk(adjacency, d, party, next, onPath, out, seen)
		delete(onPath, edge.To)
	}
}

// cloudsOn lists the providers a path passes through, in order of first
// appearance. More than one is the case nothing else follows.
func cloudsOn(start model.Provider, hops []model.Hop) []model.Provider {
	var out []model.Provider
	add := func(p model.Provider) {
		if p == "" {
			return
		}
		for _, existing := range out {
			if existing == p {
				return
			}
		}
		out = append(out, p)
	}
	add(start)
	for _, h := range hops {
		add(h.FromProvider)
		add(h.Provider)
	}
	return out
}

// weakestLink names the loosest thing on the path. It is almost always the
// entry point, because an impersonation binding names one identity while a
// federation binding can name a whole platform.
func weakestLink(p model.ExternalParty) string {
	switch p.Scope {
	case model.ScopeAnyone:
		return "the entry point admits anyone: " + p.Display
	case model.ScopeOrg:
		return "the entry point admits a whole organization: " + p.Display
	case model.ScopeDomain:
		return "the entry point admits a whole domain: " + p.Display
	case model.ScopeAccount:
		return "the entry point admits a whole account: " + p.Display
	case model.ScopeUnknown:
		return "the entry point could not be pinned down: " + p.Display
	}
	return "the entry point is pinned to " + p.Display
}

// --- findings ----------------------------------------------------------------

// chainRules splits the chains between FD030 - a chain inside one cloud - and
// FD031 - a chain that crosses a cloud boundary. They are different problems:
// one is a permissions mistake, the other is a gap between two tools that each
// believe they have full coverage.
func (c *evalContext) chainRules() {
	for _, chain := range c.res.Chains {
		switch {
		case chain.CrossCloud():
			c.fd031(chain)
		case chain.TerminalPrivileged, chain.TerminalSensitivity == model.SensitivityData:
			c.fd030(chain)
		}
	}
}

func (c *evalContext) fd030(chain model.Chain) {
	sev := model.SeverityHigh
	if chain.Entry.Scope == model.ScopeAnyone || chain.Entry.Scope == model.ScopeDomain {
		sev = model.SeverityCritical
	}

	f := model.Finding{
		ID:       "FD030",
		Severity: sev,
		Title: chain.Entry.Display + " reaches " + model.ShortName(chain.Terminal) +
			" in " + strconv.Itoa(chain.Length()) + " hops",
		Provider:      chain.Provider,
		AccountID:     accountOfChain(c.res, chain),
		ResourceARN:   chain.EntryVia,
		ResourceName:  model.ShortName(chain.Terminal),
		ExternalParty: chain.Entry.Display,
		WhatIsWrong: "This is a chain, not a single grant. " + chain.Entry.Display +
			" can become " + model.ShortName(chain.Hops[0].To) + ", which can reach " +
			model.ShortName(chain.Terminal) + ", and that identity " + terminalPhrase(chain) + ".",
		AttackerCan: "Compromise the entry point and follow the chain to " +
			model.ShortName(chain.Terminal) + " - " + firstReason(chain.TerminalReasons) +
			". Nothing in the first hop looks unusual.",
		Evidence: chainEvidence(chain),
		Fix: model.Fix{
			Summary: "Break the chain at its weakest link, which is usually the entry point.",
			Steps:   chainFixSteps(chain),
		},
	}
	c.add(f)
}

// FD031 - the chain leaves the cloud it started in.
func (c *evalContext) fd031(chain model.Chain) {
	sev := model.SeverityHigh
	if chain.Entry.Scope == model.ScopeAnyone || chain.Entry.Scope == model.ScopeDomain ||
		chain.TerminalPrivileged || chain.TerminalSensitivity == model.SensitivityData {
		sev = model.SeverityCritical
	}

	clouds := make([]string, 0, len(chain.Clouds))
	for _, p := range chain.Clouds {
		clouds = append(clouds, strings.ToUpper(string(p)))
	}
	first, last := clouds[0], clouds[len(clouds)-1]

	f := model.Finding{
		ID:            "FD031",
		Severity:      sev,
		Title:         chain.Entry.Display + " crosses " + strings.Join(clouds, " into ") + " and " + terminalPhrase(chain),
		Provider:      chain.Provider,
		AccountID:     accountOfChain(c.res, chain),
		ResourceARN:   chain.EntryVia,
		ResourceName:  model.ShortName(chain.Terminal),
		ExternalParty: chain.Entry.Display,
		WhatIsWrong: "This path leaves " + first + " and ends in " + last + ". Your " + first +
			" scanner stops at " + model.ShortName(chain.Hops[0].To) + ", and your " + last +
			" scanner never sees where the caller came from, so neither of them reports it.",
		AttackerCan: "Compromise " + chain.Entry.Display + " once and end up in a different cloud, " +
			"where it " + terminalPhrase(chain) + ".",
		Evidence: chainEvidence(chain),
		Fix: model.Fix{
			Summary: "Decide whether this cloud boundary is meant to be crossed at all.",
			Steps: append([]string{
				"The crossing happens at: " + crossingDescription(chain) + ".",
			}, chainFixSteps(chain)...),
		},
	}
	c.add(f)
}

// terminalPhrase says what reaching the end of the chain means, in words.
func terminalPhrase(chain model.Chain) string {
	if len(chain.TerminalReach) > 0 {
		return reachPhrase(chain.TerminalSensitivity, chain.TerminalReach)
	}
	if chain.TerminalPrivileged {
		return "can escalate from there"
	}
	return chain.TerminalSensitivity.Describe()
}

// crossingDescription names the hop where the path changes cloud, which is the
// one place a reader can cut it in half.
func crossingDescription(chain model.Chain) string {
	for _, h := range chain.Hops {
		if h.Kind != model.EdgeCrossCloud {
			continue
		}
		return model.ShortName(h.From) + " -> " + model.ShortName(h.To) +
			" (" + string(h.FromProvider) + " into " + string(h.Provider) + ")"
	}
	return "the federation hop"
}

func chainFixSteps(chain model.Chain) []string {
	steps := []string{chain.Weakest + "."}
	if hop := removableHop(chain); hop != "" {
		steps = append(steps, "Remove the link that is not needed: "+hop+".")
	}
	return append(steps,
		"If every hop is needed, cut the terminal identity's permissions instead - "+
			"a chain into something that holds nothing is not a chain worth walking.")
}

// chainEvidence lists the path and then each hop with the binding that permits
// it. Names are shortened: the full resource ids are in the JSON, and a wall of
// them helps nobody.
func chainEvidence(chain model.Chain) []string {
	out := make([]string, 0, len(chain.Hops)+2)
	out = append(out, chain.ShortPath())
	for _, h := range chain.Hops {
		via := h.Via
		if via == "" {
			via = string(h.Kind)
		}
		line := model.HopFromLabel(h) + " -> " + model.ShortName(h.To) + " via " + via
		if h.Kind == model.EdgeCrossCloud {
			line += "  [" + string(h.FromProvider) + " -> " + string(h.Provider) + "]"
		}
		out = append(out, line)
	}
	out = append(out, chain.TerminalReasons...)
	for _, r := range chain.TerminalReach {
		out = append(out, "reaches "+r)
	}
	return out
}

// removableHop names the link most likely to be cuttable: the last one that is
// not the entry, because that is the one granting the final access.
func removableHop(chain model.Chain) string {
	for i := len(chain.Hops) - 1; i >= 1; i-- {
		h := chain.Hops[i]
		if h.Via == "" {
			continue
		}
		return h.Via + " for " + model.ShortName(h.From) + " on " + model.ShortName(h.To)
	}
	return ""
}

func accountOfChain(res *model.Result, chain model.Chain) string {
	for _, d := range res.Doors {
		if d.ResourceARN == chain.EntryVia {
			return d.AccountID
		}
	}
	return ""
}

func firstOrEmpty(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
