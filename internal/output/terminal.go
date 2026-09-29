package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// The terminal report has one job: make an invisible problem obvious in five
// seconds. It leads with a map of who can get in - external party on the left,
// what they reach on the right - because that picture is the whole pitch, then
// goes finding by finding with the exact text to paste.

const (
	indent     = "  "
	labelWidth = 10
)

// glyphs are the box-drawing characters. A terminal that renders colour will
// render U+2500; one that will not gets ASCII, because a report full of
// mojibake is worse than a plain one.
type glyphs struct {
	rule  string
	bar   string
	arrow string
}

func glyphsFor(unicode bool) glyphs {
	if unicode {
		return glyphs{rule: "─", bar: "▐", arrow: "→"}
	}
	return glyphs{rule: "-", bar: "|", arrow: "->"}
}

// Terminal writes the human report.
func Terminal(w io.Writer, res *model.Result, opts Options) error {
	p := paint{on: opts.Color}
	g := glyphsFor(opts.Color)
	width := opts.width()

	header(w, p, res, width)
	doorMap(w, p, g, res, width)
	chainMap(w, p, g, res, width)
	findingSections(w, p, g, res, width, opts)
	scanGaps(w, p, g, res, width)
	footer(w, p, res, opts)
	return nil
}

// chainMap draws how far an outside identity actually gets. This is the part
// of the report that surprises people: every hop looks reasonable on its own,
// and the picture only appears when they are stacked.
func chainMap(w io.Writer, p paint, g glyphs, res *model.Result, width int) {
	var worth []model.Chain
	for _, c := range res.Chains {
		if chainWorthShowing(c) {
			worth = append(worth, c)
		}
	}
	if len(worth) == 0 {
		return
	}
	shown := worth
	if len(shown) > 8 {
		shown = shown[:8] // res.Chains is already ranked by risk
	}

	section(w, p, g, "HOW FAR THEY GET", width)

	for i, c := range shown {
		fmt.Fprintln(w, indent+indent+p.bold(c.Entry.Display))

		for depth, h := range c.Hops {
			pad := indent + indent + indent + strings.Repeat("  ", depth)
			line := pad + p.dim(g.arrow+" ")

			// A hop that changes cloud is the whole point, so it is marked
			// where the eye lands rather than left to the JSON.
			if h.Kind == model.EdgeCrossCloud {
				line += p.bold("["+string(h.Provider)+"] ") + short(h.To)
			} else {
				line += short(h.To)
			}

			switch {
			case len(h.ToReach) > 0:
				line += p.red("   " + strings.Join(h.ToReach, ", "))
			case h.ToPrivileged:
				line += p.red("   " + firstOrDefault(h.ToReasons, "privileged"))
			case h.Via != "":
				line += p.dim("   " + shortRole(h.Via))
			}
			fmt.Fprintln(w, line)
		}

		// The sentence someone forwards. It is the reason the section exists.
		if line := chainHeadline(c); line != "" {
			fmt.Fprintln(w, indent+indent+indent+p.bold(line))
		}
		if i < len(shown)-1 {
			fmt.Fprintln(w)
		}
	}

	if len(res.Chains) > len(shown) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, indent+indent+p.dim(fmt.Sprintf(
			"%d more chain(s) in the JSON, including ones that end somewhere harmless.",
			len(res.Chains)-len(shown))))
	}
	fmt.Fprintln(w)
}

// chainWorthShowing keeps the section to the chains a person would act on: one
// that ends somewhere privileged, one that ends at data, or one that leaves the
// cloud it started in.
func chainWorthShowing(c model.Chain) bool {
	return c.TerminalPrivileged ||
		c.TerminalSensitivity == model.SensitivityData ||
		c.CrossCloud()
}

// chainHeadline is the one-line consequence, phrased the way a person would
// repeat it.
func chainHeadline(c model.Chain) string {
	subject := entryNoun(c.Entry)

	switch {
	case len(c.TerminalReach) > 0:
		return "One " + subject + " compromise reaches " + c.TerminalReach[0] + "."
	case c.TerminalPrivileged && c.CrossCloud():
		return "One " + subject + " compromise takes over a second cloud."
	case c.TerminalPrivileged:
		return "One " + subject + " compromise takes over the account."
	case c.CrossCloud():
		return "One " + subject + " compromise crosses into another cloud."
	}
	return ""
}

// entryNoun names the entry point in the way its platform would be spoken
// about, so the headline reads like a sentence rather than a field dump.
func entryNoun(p model.ExternalParty) string {
	switch p.Kind {
	case model.PartyGitHub:
		return "repo"
	case model.PartyGitLab, model.PartyBitbucket:
		return "project"
	case model.PartyCircleCI, model.PartyBuildkite:
		return "pipeline"
	case model.PartyTerraformCloud:
		return "workspace"
	case model.PartyVercel:
		return "deployment"
	case model.PartyAWSAccount:
		return "account"
	case model.PartyGoogleDomain, model.PartyGoogleAccount, model.PartyGoogleGroup:
		return "Google account"
	case model.PartySAMLIdP:
		return "employee account"
	}
	return "entry point"
}

// shortRole trims "roles/iam.serviceAccountTokenCreator" to its readable tail.
func shortRole(role string) string {
	if i := strings.LastIndex(role, "."); i >= 0 && i+1 < len(role) {
		return role[i+1:]
	}
	return strings.TrimPrefix(role, "roles/")
}

func firstOrDefault(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return list[0]
}

func header(w io.Writer, p paint, res *model.Result, width int) {
	name := "frontdoor"
	if res.Version != "" {
		name += " " + res.Version
	}

	var scanned []string
	for _, a := range res.Accounts {
		if !a.Scanned {
			continue
		}
		label := a.ID
		if a.Alias != "" {
			label = a.Alias + " (" + a.ID + ")"
		}
		scanned = append(scanned, label)
	}

	line := p.bold(name)
	if len(scanned) > 0 {
		line += p.dim("  ·  ") + strings.Join(scanned, ", ")
	}
	if !res.GeneratedAt.IsZero() {
		line += p.dim("  ·  " + res.GeneratedAt.Format("2006-01-02 15:04 MST"))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, indent+line)
}

// doorMap is the screenshot: who is outside, and what they reach.
func doorMap(w io.Writer, p paint, g glyphs, res *model.Result, width int) {
	type row struct {
		party      string
		target     string
		privileged bool
		severity   model.Severity
	}

	worst := worstByResource(res)
	var rows []row
	for _, d := range res.Doors {
		if !d.IsExternal() {
			continue
		}
		for _, party := range d.ExternalParties {
			if party.Internal {
				continue // a seam in a chain, not a way in from outside
			}
			rows = append(rows, row{
				party:      party.Display,
				target:     short(d.ResourceARN),
				privileged: d.IsPrivileged,
				severity:   worst[d.ResourceARN],
			})
		}
	}
	if len(rows) == 0 {
		return
	}

	// Worst first: the open doors are what the reader needs to see, and a
	// screenshot usually catches only the top of the list.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].severity.Rank() != rows[j].severity.Rank() {
			return rows[i].severity.Rank() > rows[j].severity.Rank()
		}
		return rows[i].party < rows[j].party
	})

	section(w, p, g, "WHO CAN GET IN", width)

	partyCol, targetCol := 0, 0
	for _, r := range rows {
		if n := len(r.party); n > partyCol {
			partyCol = n
		}
		if n := len(r.target); n > targetCol {
			targetCol = n
		}
	}
	if limit := width - targetCol - 26; partyCol > limit && limit > 20 {
		partyCol = limit
	}

	for _, r := range rows {
		party := truncate(r.party, partyCol)
		coloured := party
		switch r.severity {
		case model.SeverityCritical:
			coloured = p.red(party)
		case model.SeverityHigh:
			coloured = p.orange(party)
		}

		line := indent + indent + coloured + spaces(partyCol-len(party)) +
			p.dim("  "+g.arrow+"  ") + r.target
		if r.privileged {
			line += spaces(targetCol-len(r.target)) + p.red("   privileged")
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

func findingSections(w io.Writer, p paint, g glyphs, res *model.Result, width int, opts Options) {
	bySeverity := map[model.Severity][]model.Finding{}
	suppressed := 0
	for _, f := range res.Findings {
		if f.Suppressed {
			suppressed++
			continue
		}
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh,
		model.SeverityMedium, model.SeverityLow, model.SeverityInfo,
	} {
		group := bySeverity[sev]
		if len(group) == 0 {
			continue
		}
		sectionColoured(w, p, g, p.severity(sev)+"  "+p.dim("("+itoa(len(group))+")"),
			len(sev)+5+len(itoa(len(group))), width)
		for i, f := range group {
			finding(w, p, f, width)
			if i < len(group)-1 {
				fmt.Fprintln(w)
			}
		}
		fmt.Fprintln(w)
	}

	if len(res.Findings) > 0 && len(bySeverity) == 0 {
		section(w, p, g, "FINDINGS", width)
		fmt.Fprintln(w, indent+indent+p.green("Nothing unsuppressed. All "+itoa(suppressed)+" findings are suppressed."))
		fmt.Fprintln(w)
	}
}

func finding(w io.Writer, p paint, f model.Finding, width int) {
	pad := indent + indent
	fmt.Fprintln(w, pad+p.bold(f.ID)+"  "+f.Title)
	if f.ResourceARN != "" {
		fmt.Fprintln(w, pad+strings.Repeat(" ", len(f.ID)+2)+p.dim(f.ResourceARN))
	}
	fmt.Fprintln(w)

	body := pad + strings.Repeat(" ", len(f.ID)+2)
	field(w, p, body, "Wrong", f.WhatIsWrong, width)
	field(w, p, body, "Attacker", f.AttackerCan, width)
	if len(f.Evidence) > 0 {
		field(w, p, body, "Evidence", strings.Join(f.Evidence, "\n"), width)
	}

	if f.Fix.Summary != "" {
		field(w, p, body, "Fix", f.Fix.Summary, width)
	}
	if f.Fix.TrustPolicy != "" {
		fmt.Fprintln(w)
		for _, line := range strings.Split(f.Fix.TrustPolicy, "\n") {
			fmt.Fprintln(w, body+strings.Repeat(" ", labelWidth)+p.blue(line))
		}
		fmt.Fprintln(w)
	}
	for _, step := range f.Fix.Steps {
		field(w, p, body, "", "- "+step, width)
	}
	if f.DocsURL != "" {
		field(w, p, body, "Docs", f.DocsURL, width)
	}
}

// field prints a labelled, wrapped paragraph. An empty label continues the
// previous one, which is how the fix steps line up.
func field(w io.Writer, p paint, pad, label, text string, width int) {
	if strings.TrimSpace(text) == "" {
		return
	}
	avail := width - len(pad) - labelWidth
	if avail < 24 {
		avail = 24
	}

	first := true
	for _, paragraph := range strings.Split(text, "\n") {
		for _, line := range wrap(paragraph, avail) {
			prefix := strings.Repeat(" ", labelWidth)
			if first && label != "" {
				prefix = padRight(p.dim(label), label, labelWidth)
			}
			fmt.Fprintln(w, pad+prefix+line)
			first = false
		}
	}
}

func scanGaps(w io.Writer, p paint, g glyphs, res *model.Result, width int) {
	var denied []string
	seen := map[string]bool{}
	for _, u := range res.Unreadable {
		if !u.Denied || seen[u.Operation] {
			continue
		}
		seen[u.Operation] = true
		denied = append(denied, u.Operation)
	}
	if len(denied) == 0 {
		return
	}
	sort.Strings(denied)

	section(w, p, g, "SCAN GAPS", width)
	fmt.Fprintln(w, indent+indent+p.yellow("This scan is incomplete.")+" These calls were denied:")
	for _, op := range denied {
		fmt.Fprintln(w, indent+indent+indent+p.dim(op))
	}
	fmt.Fprintln(w)
}

func footer(w io.Writer, p paint, res *model.Result, opts Options) {
	line := SummaryLine(res)
	if strings.Contains(line, "ANY") {
		line = p.bold(line)
	}
	fmt.Fprintln(w, indent+line)

	if len(res.Findings) > 0 {
		counts := CountsLine(res)
		if res.Counts.Critical > 0 {
			counts = p.red(counts)
		} else if res.Counts.High > 0 {
			counts = p.orange(counts)
		}
		fmt.Fprintln(w, indent+counts)
	}
	if res.Counts.Suppressed > 0 && opts.IgnorePath != "" {
		fmt.Fprintln(w, indent+p.dim("Suppressions from "+opts.IgnorePath))
	}

	// One line, dimmed, at the very end, and only when there was something to
	// find. A tool that advertises to someone whose account came back clean
	// has not earned the sentence.
	if opts.Promo && res.Counts.Total > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, indent+p.dim("Want this watched continuously across the whole estate?"))
		fmt.Fprintln(w, indent+p.dim("https://secorvia.com - free tier, no card. Set FRONTDOOR_NO_PROMO=1 to hide this."))
	}
	fmt.Fprintln(w)
}

// --- layout helpers ----------------------------------------------------------

func section(w io.Writer, p paint, g glyphs, title string, width int) {
	sectionColoured(w, p, g, p.bold(title), len(title), width)
}

// sectionColoured draws a section header whose title may already carry ANSI
// escapes, so the rule length is measured from the visible width passed in.
func sectionColoured(w io.Writer, p paint, g glyphs, title string, visible, width int) {
	rule := width - visible - len(indent) - 4
	if rule < 4 {
		rule = 4
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, indent+p.dim(g.bar)+" "+title+" "+p.dim(strings.Repeat(g.rule, rule)))
	fmt.Fprintln(w)
}

// wrap breaks text at word boundaries. A word longer than the width is left
// intact rather than chopped: ARNs and URLs must stay copy-pasteable.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = word
	}
	return append(lines, line)
}

// padRight pads a possibly-coloured string to visible width n. The plain
// argument is the same text without escapes, which is what the width is
// measured against.
func padRight(coloured, plain string, n int) string {
	if len(plain) >= n {
		return coloured + " "
	}
	return coloured + strings.Repeat(" ", n-len(plain))
}

func truncate(s string, n int) string {
	if n <= 3 || len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// short trims a resource identifier to the part a human reads.
func short(id string) string { return model.ShortName(id) }

// worstByResource is the highest severity found on each resource, used to
// colour the door map.
func worstByResource(res *model.Result) map[string]model.Severity {
	worst := map[string]model.Severity{}
	for _, f := range res.Findings {
		if f.Suppressed {
			continue
		}
		if f.Severity.Rank() > worst[f.ResourceARN].Rank() {
			worst[f.ResourceARN] = f.Severity
		}
	}
	return worst
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}
