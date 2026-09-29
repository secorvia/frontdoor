// Package rules turns collected doors into findings.
//
// A rule answers three questions and nothing else: what is wrong, what an
// attacker could do with it, and exactly what to paste to fix it. Anything a
// rule cannot say precisely, it does not say at all - a security tool that
// cries wolf gets uninstalled, and a false critical costs more trust than a
// missed medium.
package rules

import (
	"sort"
	"strings"
	"time"

	"github.com/secorvia/frontdoor/internal/model"
)

// DocsBase is where the per-rule explanations live. The CLI prints these, so
// they carry the traffic back to the project's own domain rather than GitHub.
const DocsBase = "https://secorvia.com/docs/frontdoor/"

// Options tune the thresholds that are genuinely a matter of policy.
type Options struct {
	// StaleDays is how long a role or key may go unused before it counts as
	// stale. Default 90.
	StaleDays int
	// MaxKeyAgeDays is how old an active access key may be before FD020 fires.
	// Default 90.
	MaxKeyAgeDays int
	// Now is injectable so tests are not time-dependent.
	Now time.Time
	// Ignore suppresses findings without removing them from the output.
	Ignore *IgnoreList
	// Resolved carries the results of live issuer checks, when --resolve was
	// passed. Nil means no network lookups were performed.
	Resolved map[string]ResolvedIssuer
	// ImpersonationEdges are the service-account links a collector found.
	// FD030 walks them; with none, no chain rule fires.
	ImpersonationEdges []model.Hop
}

func (o Options) staleDays() int {
	if o.StaleDays > 0 {
		return o.StaleDays
	}
	return 90
}

func (o Options) maxKeyAgeDays() int {
	if o.MaxKeyAgeDays > 0 {
		return o.MaxKeyAgeDays
	}
	return 90
}

func (o Options) now() time.Time {
	if !o.Now.IsZero() {
		return o.Now
	}
	return time.Now().UTC()
}

// Run evaluates every rule against the result and fills res.Findings and
// res.Counts.
func Run(res *model.Result, opts Options) {
	ctx := &evalContext{res: res, opts: opts, orgAccounts: orgAccountSet(res)}

	// Chains are built before the per-door rules so FD030 can read them, and
	// so the output has them whether or not any chain turns out to be a
	// finding.
	res.Chains = BuildChains(res, opts.ImpersonationEdges)

	for i := range res.Doors {
		d := &res.Doors[i]
		if !d.IsExternal() {
			continue
		}
		switch d.Provider {
		case model.ProviderGCP:
			ctx.gcpRules(d)
			continue
		case model.ProviderAzure:
			ctx.azureRules(d)
			continue
		}
		switch d.PrincipalType {
		case model.PrincipalOIDC, model.PrincipalSAML:
			ctx.federatedRules(d)
		case model.PrincipalCrossAccount:
			ctx.crossAccountRules(d)
		}
	}

	ctx.hygieneRules()
	ctx.chainRules()

	findings := ctx.findings
	if opts.Ignore != nil {
		for i := range findings {
			if reason, ok := opts.Ignore.Match(findings[i].ID, findings[i].ResourceARN); ok {
				findings[i].Suppressed = true
				findings[i].SuppressReason = reason
			}
		}
	}

	sortFindings(findings)
	res.Findings = findings
	res.Counts = model.Tally(findings)
}

// evalContext carries the scan-wide facts a rule needs and collects findings.
type evalContext struct {
	res         *model.Result
	opts        Options
	orgAccounts map[string]bool
	findings    []model.Finding
}

func (c *evalContext) add(f model.Finding) {
	if f.DocsURL == "" {
		f.DocsURL = DocsBase + f.ID
	}
	if f.Provider == "" {
		f.Provider = model.ProviderAWS
	}
	c.findings = append(c.findings, f)
}

// fromDoor pre-fills the resource identity every finding shares.
func fromDoor(d *model.Door, id string, sev model.Severity, title string) model.Finding {
	return model.Finding{
		ID:           id,
		Severity:     sev,
		Title:        title,
		Provider:     d.Provider,
		AccountID:    d.AccountID,
		ResourceARN:  d.ResourceARN,
		ResourceName: d.ResourceName,
		Issuer:       d.Issuer,
	}
}

// orgAccountSet is every account id known to be in the caller's organization.
func orgAccountSet(res *model.Result) map[string]bool {
	set := map[string]bool{}
	for _, a := range res.Accounts {
		if a.InOrg || a.Scanned {
			set[a.ID] = true
		}
	}
	return set
}

// orgKnown reports whether the organization layout was actually readable.
// When it was not, rules that depend on "is this account one of ours" must say
// so rather than assume the worst.
func (c *evalContext) orgKnown() bool {
	for _, a := range c.res.Accounts {
		if a.InOrg {
			return true
		}
	}
	return false
}

// externalDoorCount is how many ways in the account has, used by FD020.
func (c *evalContext) externalDoorCount(accountID string) int {
	n := 0
	for _, d := range c.res.Doors {
		if d.AccountID == accountID && d.IsExternal() {
			n++
		}
	}
	return n
}

// --- shared helpers ----------------------------------------------------------

// conditionEvidence renders a condition the way it appears in the policy.
func conditionEvidence(c model.Condition) string {
	return c.Operator + " " + c.Key + " = " + strings.Join(c.Values, ", ")
}

// doorEvidence lists every condition on the door, or says there are none.
func doorEvidence(d *model.Door) []string {
	if len(d.Conditions) == 0 {
		return []string{"the statement has no Condition block at all"}
	}
	out := make([]string, 0, len(d.Conditions))
	for _, c := range d.Conditions {
		out = append(out, conditionEvidence(c))
	}
	return out
}

// narrowingKeys are conditions that meaningfully restrict who gets in, even
// when the principal itself is wide. A door held by one of these is not the
// same as a door held by nothing.
var narrowingKeys = map[string]string{
	"aws:principalorgid":    "aws:PrincipalOrgID",
	"aws:principalorgpaths": "aws:PrincipalOrgPaths",
	"aws:principalarn":      "aws:PrincipalArn",
	"aws:principalaccount":  "aws:PrincipalAccount",
	"sts:externalid":        "sts:ExternalId",
	"aws:sourcearn":         "aws:SourceArn",
	"aws:sourceaccount":     "aws:SourceAccount",
	"aws:sourceip":          "aws:SourceIp",
	"aws:sourcevpc":         "aws:SourceVpc",
	"aws:sourcevpce":        "aws:SourceVpce",
}

// narrowingConditions returns the restricting conditions present on a door.
func narrowingConditions(d *model.Door) []string {
	var out []string
	for _, c := range d.Conditions {
		if name, ok := narrowingKeys[strings.ToLower(c.Key)]; ok && !c.HasWildcard() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// daysSince returns whole days between t and now, or -1 when t is unknown.
func daysSince(t *time.Time, now time.Time) int {
	if t == nil || t.IsZero() {
		return -1
	}
	return int(now.Sub(*t).Hours() / 24)
}

// sortFindings orders by severity, then rule id, then resource, so two runs
// over an unchanged account produce byte-identical output.
func sortFindings(f []model.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity.Rank() != f[j].Severity.Rank() {
			return f[i].Severity.Rank() > f[j].Severity.Rank()
		}
		if f[i].ID != f[j].ID {
			return f[i].ID < f[j].ID
		}
		if f[i].ResourceARN != f[j].ResourceARN {
			return f[i].ResourceARN < f[j].ResourceARN
		}
		return f[i].ExternalParty < f[j].ExternalParty
	})
}
