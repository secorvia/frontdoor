package model

// A door tells you who can get in. A chain tells you how far they get.
//
// The interesting case is never the first hop: a GitHub repository that can
// impersonate a build service account looks fine until you notice that service
// account can impersonate the one with roles/owner. Reporting only the first
// hop hides exactly the thing worth knowing, so a chain always carries its
// full path.

// EdgeKind is how one node reaches the next.
type EdgeKind string

const (
	// EdgeFederation is an outside identity entering a cloud.
	EdgeFederation EdgeKind = "federation"
	// EdgeImpersonation is a GCP service account acting as another.
	EdgeImpersonation EdgeKind = "impersonation"
	// EdgeAssumeRole is an AWS role assuming another role.
	EdgeAssumeRole EdgeKind = "assume_role"
	// EdgeCrossCloud is a trust edge that leaves one cloud for another.
	// Phase 5 populates these.
	EdgeCrossCloud EdgeKind = "cross_cloud"
)

// Hop is one step along a chain.
type Hop struct {
	Kind     EdgeKind `json:"kind"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Via      string   `json:"via,omitempty"`      // the role or binding that permits it
	Provider Provider `json:"provider,omitempty"` // the cloud the target lives in
	Detail   string   `json:"detail,omitempty"`

	// ToPrivileged says whether the thing this hop reaches can escalate, and
	// ToSensitivity what kind of thing it is. Both travel on the edge because
	// a service account that is only ever a chain target has no door of its
	// own to carry the answer.
	ToPrivileged  bool        `json:"to_privileged,omitempty"`
	ToReasons     []string    `json:"to_reasons,omitempty"`
	ToSensitivity Sensitivity `json:"to_sensitivity,omitempty"`
	ToReach       []string    `json:"to_reach,omitempty"`
	FromProvider  Provider    `json:"from_provider,omitempty"`
}

// Chain is one path from an outside identity to something it can reach.
type Chain struct {
	Provider Provider      `json:"provider"`
	Entry    ExternalParty `json:"entry"`
	EntryVia string        `json:"entry_via,omitempty"` // the door ARN or resource the chain starts at
	Hops     []Hop         `json:"hops"`

	// Terminal is the last thing on the path, and TerminalPrivileged says
	// whether reaching it is a takeover rather than an inconvenience.
	Terminal            string      `json:"terminal"`
	TerminalPrivileged  bool        `json:"terminal_privileged"`
	TerminalReasons     []string    `json:"terminal_reasons,omitempty"`
	TerminalSensitivity Sensitivity `json:"terminal_sensitivity,omitempty"`
	TerminalReach       []string    `json:"terminal_reach,omitempty"`

	// Clouds is every provider the path passes through, in order of first
	// appearance. More than one means the chain leaves the cloud it started
	// in - which is the case no other scanner follows.
	Clouds []Provider `json:"clouds,omitempty"`

	// Weakest is the loosest condition anywhere on the path. A chain is only
	// as strong as its weakest link, and that is usually the entry point.
	Weakest string `json:"weakest_link,omitempty"`
}

// CrossCloud reports whether the path leaves the cloud it started in.
func (c Chain) CrossCloud() bool { return len(c.Clouds) > 1 }

// Length is the hop count.
func (c Chain) Length() int { return len(c.Hops) }

// Path renders the chain as "a -> b -> c".
func (c Chain) Path() string {
	if len(c.Hops) == 0 {
		return c.Entry.Display
	}
	out := c.Hops[0].From
	for _, h := range c.Hops {
		out += " -> " + h.To
	}
	return out
}

// Risk ranks chains for reporting: how loose the entry point is, multiplied by
// how sensitive the terminal is. Length is deliberately not a factor - a short
// chain into an owner account beats a long one into a log bucket.
func (c Chain) Risk() int {
	entry := 1
	switch c.Entry.Scope {
	case ScopeAnyone:
		entry = 8
	case ScopeDomain:
		entry = 5
	case ScopeOrg:
		entry = 4
	case ScopeAccount:
		entry = 3
	case ScopeProject:
		entry = 2
	}

	terminal := c.TerminalSensitivity.Weight()
	if c.TerminalPrivileged && terminal < SensitivityAdmin.Weight() {
		terminal = SensitivityAdmin.Weight()
	}

	risk := entry * terminal
	if c.CrossCloud() {
		// A path that crosses clouds is one nobody's existing tooling is
		// watching: the AWS scanner stops at the role and the GCP scanner
		// never sees where the caller came from.
		risk += 10
	}
	return risk
}

// ShortName trims a resource identifier down to the part a person reads.
// AWS ARNs and GCP resource paths are both long enough to ruin a terminal
// column, and neither tail is ambiguous in practice.
//
//	arn:aws:iam::111122223333:role/ci-deploy                       -> role/ci-deploy
//	projects/acme/serviceAccounts/ci@acme.iam.gserviceaccount.com  -> ci@acme
//	ci@acme.iam.gserviceaccount.com                                -> ci@acme
func ShortName(id string) string {
	if id == "" {
		return ""
	}

	// AWS ARN: everything after the last colon is the resource.
	if len(id) > 4 && id[:4] == "arn:" {
		if i := lastIndexByte(id, ':'); i >= 0 && i+1 < len(id) {
			return id[i+1:]
		}
		return id
	}

	// GCP resource path: the last segment names the thing.
	if i := lastIndexByte(id, '/'); i >= 0 && i+1 < len(id) {
		id = id[i+1:]
	}

	// GCP service account email: the domain is the same for every one of them.
	const saSuffix = ".iam.gserviceaccount.com"
	if at := indexByte(id, '@'); at >= 0 {
		host := id[at+1:]
		if hasSuffix(host, saSuffix) {
			return id[:at+1] + host[:len(host)-len(saSuffix)]
		}
	}
	return id
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// ShortPath renders the chain with every resource shortened, which is the form
// that fits in a terminal and in a finding title.
//
// The entry point is left alone. It is a party description, not a resource id
// - "github.com/acme/api @ refs/heads/main" trimmed at its last slash becomes
// "main", which is both wrong and unhelpful.
func (c Chain) ShortPath() string {
	if len(c.Hops) == 0 {
		return c.Entry.Display
	}
	out := HopFromLabel(c.Hops[0])
	for _, h := range c.Hops {
		out += " -> " + ShortName(h.To)
	}
	return out
}

// HopFromLabel renders the source of a hop: a party description at the entry,
// a resource id everywhere else.
func HopFromLabel(h Hop) string {
	if h.Kind == EdgeFederation {
		return h.From
	}
	return ShortName(h.From)
}
