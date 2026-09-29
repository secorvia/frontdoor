package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// Mermaid renders the trust graph for a README. GitHub renders mermaid blocks
// natively, so this is the cheapest way for someone to show their team what
// the account's front doors actually look like.
//
// Phase 5 extends this graph across clouds; the node and edge shapes here are
// chosen so that extension is additive.

// Mermaid writes a mermaid flowchart of every external door.
func Mermaid(w io.Writer, res *model.Result) error {
	worst := worstByResource(res)

	type edge struct {
		party      string
		target     string
		severity   model.Severity
		privileged bool
		crossCloud bool
		label      string
	}
	var edges []edge
	for _, d := range res.Doors {
		if !d.IsExternal() {
			continue
		}
		for _, p := range d.ExternalParties {
			if p.Internal {
				continue // the chain already draws this hop
			}
			edges = append(edges, edge{
				party:      p.Display,
				target:     short(d.ResourceARN),
				severity:   worst[d.ResourceARN],
				privileged: d.IsPrivileged,
			})
		}
	}

	// The hops are what make the graph worth drawing: without them it is a
	// list of doors, and with them it is a picture of how far each one
	// reaches. Only the chains a person would act on are drawn, or the graph
	// turns into noise on a large estate.
	for _, c := range res.Chains {
		if !c.TerminalPrivileged && c.TerminalSensitivity != model.SensitivityData && !c.CrossCloud() {
			continue
		}
		for _, h := range c.Hops {
			if h.Kind == model.EdgeFederation {
				continue // already drawn from the door
			}
			edges = append(edges, edge{
				party:      short(h.From),
				target:     short(h.To),
				severity:   chainSeverity(h),
				privileged: h.ToPrivileged,
				crossCloud: h.Kind == model.EdgeCrossCloud,
				label:      hopLabel(h),
			})
		}
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].severity.Rank() != edges[j].severity.Rank() {
			return edges[i].severity.Rank() > edges[j].severity.Rank()
		}
		if edges[i].party != edges[j].party {
			return edges[i].party < edges[j].party
		}
		return edges[i].target < edges[j].target
	})

	fmt.Fprintln(w, "```mermaid")
	fmt.Fprintln(w, "graph LR")

	if len(edges) == 0 {
		fmt.Fprintln(w, "  none[\"No external identity can enter this account\"]")
		fmt.Fprintln(w, "  classDef clean fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20;")
		fmt.Fprintln(w, "  class none clean;")
		fmt.Fprintln(w, "```")
		return nil
	}

	// Stable ids: a mermaid node id cannot contain punctuation, and the same
	// label must always map to the same id or the graph grows duplicates.
	//
	// One id space for both ends of an edge, not two. A service account is the
	// target of a federation edge and the source of an impersonation edge, and
	// with separate spaces it would become two nodes - which is exactly the
	// chain, drawn as though it were not one.
	nodeID := newIDs("N")

	// One class per node, decided by the worst edge touching it. A party that
	// reaches both a critical door and a clean one is a critical party, so the
	// classes are ranked rather than appended in encounter order.
	classRank := map[string]int{"ok": 0, "resource": 0, "high": 1, "privileged": 1, "critical": 2}
	nodeClass := map[string]string{}
	var nodeOrder []string

	assign := func(id, class string) {
		if existing, seen := nodeClass[id]; seen {
			if classRank[class] <= classRank[existing] {
				return
			}
		} else {
			nodeOrder = append(nodeOrder, id)
		}
		nodeClass[id] = class
	}

	for _, e := range edges {
		pid := nodeID.get(e.party)
		tid := nodeID.get(e.target)

		// A labelled, thicker arrow for the hop that leaves one cloud for
		// another: it is the edge no other tool draws at all.
		switch {
		case e.crossCloud:
			fmt.Fprintf(w, "  %s[%s] ==>|%s| %s[%s]\n",
				pid, mermaidLabel(e.party), mermaidEdgeLabel(e.label), tid, mermaidLabel(e.target))
		case e.label != "":
			fmt.Fprintf(w, "  %s[%s] -->|%s| %s[%s]\n",
				pid, mermaidLabel(e.party), mermaidEdgeLabel(e.label), tid, mermaidLabel(e.target))
		default:
			fmt.Fprintf(w, "  %s[%s] --> %s[%s]\n",
				pid, mermaidLabel(e.party), tid, mermaidLabel(e.target))
		}

		switch e.severity {
		case model.SeverityCritical:
			assign(pid, "critical")
		case model.SeverityHigh:
			assign(pid, "high")
		default:
			assign(pid, "ok")
		}
		if e.privileged {
			assign(tid, "privileged")
		} else {
			assign(tid, "resource")
		}
	}

	classed := map[string][]string{}
	for _, id := range nodeOrder {
		class := nodeClass[id]
		classed[class] = append(classed[class], id)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  classDef critical fill:#ffebee,stroke:#c62828,color:#b71c1c,stroke-width:2px;")
	fmt.Fprintln(w, "  classDef high fill:#fff3e0,stroke:#ef6c00,color:#e65100;")
	fmt.Fprintln(w, "  classDef ok fill:#f5f5f5,stroke:#9e9e9e,color:#424242;")
	fmt.Fprintln(w, "  classDef privileged fill:#fce4ec,stroke:#ad1457,color:#880e4f,stroke-width:2px;")
	fmt.Fprintln(w, "  classDef resource fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;")

	for _, class := range []string{"critical", "high", "ok", "privileged", "resource"} {
		nodes := classed[class]
		if len(nodes) == 0 {
			continue
		}
		fmt.Fprintf(w, "  class %s %s;\n", strings.Join(nodes, ","), class)
	}

	fmt.Fprintln(w, "```")
	return nil
}

// ids hands out stable, mermaid-safe node ids.
type ids struct {
	prefix string
	seen   map[string]string
}

func newIDs(prefix string) *ids {
	return &ids{prefix: prefix, seen: map[string]string{}}
}

func (i *ids) get(label string) string {
	if id, ok := i.seen[label]; ok {
		return id
	}
	id := fmt.Sprintf("%s%d", i.prefix, len(i.seen))
	i.seen[label] = id
	return id
}

// mermaidLabel quotes a label and neutralises the characters that break the
// parser. Quotes inside a quoted label are the usual culprit, and ARNs and
// subject claims are full of brackets.
func mermaidLabel(s string) string {
	r := strings.NewReplacer(
		`"`, "'",
		"[", "(",
		"]", ")",
		"{", "(",
		"}", ")",
		"|", "/",
		"<", "",
		">", "",
		"\n", " ",
	)
	return `"` + r.Replace(s) + `"`
}

// chainSeverity colours an impersonation hop by what it reaches, so the eye
// lands on the end of the chain rather than the middle of it.
func chainSeverity(h model.Hop) model.Severity {
	switch {
	case h.ToPrivileged:
		return model.SeverityHigh
	case h.ToSensitivity == model.SensitivityData:
		return model.SeverityHigh
	}
	return model.SeverityInfo
}

// hopLabel names the mechanism of a hop, which is the thing a reader needs to
// know to go and remove it.
func hopLabel(h model.Hop) string {
	switch h.Kind {
	case model.EdgeCrossCloud:
		return strings.ToUpper(string(h.FromProvider)) + " to " + strings.ToUpper(string(h.Provider))
	case model.EdgeImpersonation:
		return shortRole(h.Via)
	case model.EdgeAssumeRole:
		return "assume"
	}
	return ""
}

// mermaidEdgeLabel escapes a label for the |...| edge syntax, where a pipe or
// a quote ends the label early and breaks the whole diagram.
func mermaidEdgeLabel(s string) string {
	r := strings.NewReplacer("|", "/", `"`, "'", "\n", " ", "[", "(", "]", ")")
	return r.Replace(s)
}
