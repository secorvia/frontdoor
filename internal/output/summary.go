package output

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// The summary line is the part people quote. It has to be true, short, and
// understandable by someone who has never used the tool - so it counts
// identities rather than resources, and names the platform rather than the
// rule id.

// openPhrase turns a wide-open party into the sentence people repeat.
var openPhrase = map[model.PartyKind]string{
	model.PartyGitHub:         "ANY GitHub repository",
	model.PartyGitLab:         "ANY GitLab project",
	model.PartyCircleCI:       "ANY CircleCI project",
	model.PartyTerraformCloud: "ANY Terraform Cloud workspace",
	model.PartyVercel:         "ANY Vercel project",
	model.PartyBuildkite:      "ANY Buildkite pipeline",
	model.PartyBitbucket:      "ANY Bitbucket repository",
	model.PartyGoogle:         "ANY Google identity",
	model.PartyCognito:        "ANY Cognito identity",
	model.PartySAMLIdP:        "ANY user of your SAML provider",
	model.PartyAnyone:         "ANY AWS principal",
}

// Stats are the counts the summary and the report footer share.
type Stats struct {
	Doors      int
	Identities int
	Accounts   int
	// Providers is how many distinct clouds were scanned. "your clouds" is
	// plural because of this, not because of the account count - ten AWS
	// accounts are still one cloud.
	Providers  int
	Privileged int
	WideOpen   int
	// OpenKinds is the set of platforms that accept anyone, most common first.
	OpenKinds []model.PartyKind
	Denied    int
}

// Summarise counts the external doors. Service-principal trusts are not doors
// from outside and are never counted.
func Summarise(res *model.Result) Stats {
	var s Stats
	kindCount := map[model.PartyKind]int{}

	for _, d := range res.Doors {
		if !d.IsExternal() {
			continue
		}
		s.Doors++
		if d.IsPrivileged {
			s.Privileged++
		}
		for _, p := range d.ExternalParties {
			if p.Internal {
				continue // counted as part of a chain, not as a separate way in
			}
			s.Identities++
			if p.Scope == model.ScopeAnyone {
				s.WideOpen++
				kindCount[p.Kind]++
			}
		}
	}
	providers := map[model.Provider]bool{}
	for _, a := range res.Accounts {
		if a.Scanned {
			s.Accounts++
			providers[a.Provider] = true
		}
	}
	s.Providers = len(providers)
	for _, u := range res.Unreadable {
		if u.Denied {
			s.Denied++
		}
	}

	for k := range kindCount {
		s.OpenKinds = append(s.OpenKinds, k)
	}
	sort.Slice(s.OpenKinds, func(i, j int) bool {
		if kindCount[s.OpenKinds[i]] != kindCount[s.OpenKinds[j]] {
			return kindCount[s.OpenKinds[i]] > kindCount[s.OpenKinds[j]]
		}
		return s.OpenKinds[i] < s.OpenKinds[j]
	})
	return s
}

// SummaryLine is the shareable sentence, with no ANSI and no trailing newline.
//
//	"14 external identities can enter your clouds. 1 accepts ANY GitHub repository."
func SummaryLine(res *model.Result) string {
	s := Summarise(res)

	clouds := plural(max(s.Providers, 1), "cloud", "clouds")
	if s.Identities == 0 {
		return "No external identity can enter your " + clouds + "."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d external %s can enter your %s.",
		s.Identities, plural(s.Identities, "identity", "identities"), clouds)

	switch {
	case s.WideOpen == 0:
	case len(s.OpenKinds) == 1:
		fmt.Fprintf(&b, " %d %s %s.",
			s.WideOpen, plural(s.WideOpen, "accepts", "accept"), phraseFor(s.OpenKinds[0]))
	default:
		fmt.Fprintf(&b, " %d %s ANY caller from their issuer.",
			s.WideOpen, plural(s.WideOpen, "accepts", "accept"))
	}

	// The cross-cloud sentence goes last because it is the one people quote,
	// and because no other scanner can produce it.
	if worst := worstCrossCloud(res); worst != nil {
		b.WriteString(" " + crossCloudSentence(*worst))
	}
	return b.String()
}

// worstCrossCloud returns the highest-risk path that leaves the cloud it
// started in, or nil when none does.
func worstCrossCloud(res *model.Result) *model.Chain {
	for i := range res.Chains {
		if res.Chains[i].CrossCloud() {
			return &res.Chains[i] // already ranked by risk
		}
	}
	return nil
}

// crossCloudSentence is the headline the chain earns.
func crossCloudSentence(c model.Chain) string {
	clouds := make([]string, 0, len(c.Clouds))
	for _, p := range c.Clouds {
		clouds = append(clouds, strings.ToUpper(string(p)))
	}
	route := strings.Join(clouds, " into ")

	if len(c.TerminalReach) > 0 {
		return "One of them crosses " + route + " and reaches " + c.TerminalReach[0] + "."
	}
	if c.TerminalPrivileged {
		return "One of them crosses " + route + " and can take over what it finds there."
	}
	return "One of them crosses " + route + "."
}

func phraseFor(k model.PartyKind) string {
	if p, ok := openPhrase[k]; ok {
		return p
	}
	return "ANY caller from its issuer"
}

// Summary writes the summary line plus the finding counts and any scan gaps.
// It goes to stderr in the machine-readable formats so piping stays clean.
func Summary(w io.Writer, res *model.Result) {
	fmt.Fprintln(w, SummaryLine(res))

	if len(res.Findings) > 0 {
		fmt.Fprintln(w, CountsLine(res))
	}
	if s := Summarise(res); s.Denied > 0 {
		fmt.Fprintf(w, "%d call(s) were denied - this scan is incomplete. See .unreadable in the JSON.\n", s.Denied)
	}
}

// CountsLine renders the finding tally, omitting empty severities so the line
// stays readable on a mostly-clean account.
func CountsLine(res *model.Result) string {
	c := res.Counts
	if c.Total == 0 && c.Suppressed == 0 {
		return "No findings."
	}

	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{
		{c.Critical, "critical"}, {c.High, "high"},
		{c.Medium, "medium"}, {c.Low, "low"}, {c.Info, "info"},
	} {
		if p.n > 0 {
			parts = append(parts, strconv.Itoa(p.n)+" "+p.name)
		}
	}

	line := strconv.Itoa(c.Total) + " " + plural(c.Total, "finding", "findings")
	if len(parts) > 0 {
		line += ": " + strings.Join(parts, ", ")
	}
	if c.Suppressed > 0 {
		line += fmt.Sprintf(" (%d suppressed)", c.Suppressed)
	}
	return line + "."
}

// Headline is the worst thing found, for a one-line status.
func Headline(res *model.Result) string {
	worst := ""
	for _, f := range res.Findings {
		if f.Suppressed {
			continue
		}
		if f.Severity == model.SeverityCritical {
			return f.Title
		}
		if worst == "" && f.Severity == model.SeverityHigh {
			worst = f.Title
		}
	}
	return worst
}

// ExitCode returns 1 when any unsuppressed finding is at or above failOn.
func ExitCode(res *model.Result, failOn model.Severity) int {
	for _, f := range res.Findings {
		if !f.Suppressed && f.Severity.AtLeast(failOn) {
			return 1
		}
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
