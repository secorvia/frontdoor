package rules

import (
	"sort"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// A finding without a fix is a complaint. Every rule here generates a
// Condition block built from the door's real issuer, and from its real org and
// repository when the policy already told us what they are - so in the common
// case the user pastes it unchanged.

// condBuilder assembles an IAM Condition block.
type condBuilder struct {
	equals map[string]string
	likes  map[string]string
}

func newCond() *condBuilder {
	return &condBuilder{equals: map[string]string{}, likes: map[string]string{}}
}

func (b *condBuilder) eq(key, value string) *condBuilder {
	if key != "" && value != "" {
		b.equals[key] = value
	}
	return b
}

func (b *condBuilder) like(key, value string) *condBuilder {
	if key != "" && value != "" {
		b.likes[key] = value
	}
	return b
}

// render produces the Condition fragment, indented to sit inside a statement.
func (b *condBuilder) render() string {
	var blocks []string
	if len(b.equals) > 0 {
		blocks = append(blocks, renderOperator("StringEquals", b.equals))
	}
	if len(b.likes) > 0 {
		blocks = append(blocks, renderOperator("StringLike", b.likes))
	}
	if len(blocks) == 0 {
		return ""
	}
	return "\"Condition\": {\n" + strings.Join(blocks, ",\n") + "\n}"
}

func renderOperator(op string, kv map[string]string) string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, "    \""+k+"\": \""+escapeJSON(kv[k])+"\"")
	}
	return "  \"" + op + "\": {\n" + strings.Join(lines, ",\n") + "\n  }"
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// audienceFor returns the audience to pin. The provider's own registered
// client ID is authoritative; falling back to a guess would be worse than a
// placeholder, so the placeholder is explicit.
func audienceFor(d *model.Door) string {
	if len(d.Audiences) > 0 {
		return d.Audiences[0]
	}
	if model.NormalizeIssuer(d.Issuer) == "token.actions.githubusercontent.com" {
		return "sts.amazonaws.com"
	}
	return "AUDIENCE_REGISTERED_ON_THE_PROVIDER"
}

// subjectTemplate is the tightest sub value that still makes sense for the
// platform, filled in with whatever the current policy already told us.
func subjectTemplate(d *model.Door, p *model.ExternalParty) string {
	org := orDefault(p.Org, "YOUR_ORG")
	project := orDefault(p.Project, "YOUR_REPO")

	switch p.Kind {
	case model.PartyGitHub:
		switch {
		case p.Environment != "" && !hasGlob(p.Environment):
			return "repo:" + org + "/" + project + ":environment:" + p.Environment
		case p.Ref != "" && !hasGlob(p.Ref):
			return "repo:" + org + "/" + project + ":ref:" + p.Ref
		default:
			return "repo:" + org + "/" + project + ":ref:refs/heads/main"
		}
	case model.PartyGitLab:
		path := orDefault(p.Project, "YOUR_GROUP/YOUR_PROJECT")
		ref := orDefault(stripGlob(p.Ref), "main")
		return "project_path:" + path + ":ref_type:branch:ref:" + ref
	case model.PartyCircleCI:
		return "org/" + orDefault(p.Org, "ORG_UUID") + "/project/" + orDefault(p.Project, "PROJECT_UUID") + "/user/*"
	case model.PartyTerraformCloud:
		return "organization:" + org + ":project:" + orDefault(p.Project, "YOUR_PROJECT") +
			":workspace:" + orDefault(stripGlob(p.Environment), "YOUR_WORKSPACE") + ":run_phase:apply"
	case model.PartyVercel:
		return "owner:" + org + ":project:" + orDefault(p.Project, "YOUR_PROJECT") +
			":environment:" + orDefault(stripGlob(p.Environment), "production")
	case model.PartyBuildkite:
		return "organization:" + org + ":pipeline:" + orDefault(p.Project, "YOUR_PIPELINE") +
			":ref:" + orDefault(stripGlob(p.Ref), "refs/heads/main") + ":*"
	case model.PartyBitbucket:
		return orDefault(p.Project, "{REPOSITORY_UUID}") + ":*"
	case model.PartyGoogle:
		return orDefault(p.Actor, "SERVICE_ACCOUNT_UNIQUE_ID")
	default:
		return "THE_EXACT_SUBJECT_YOU_INTEND_TO_TRUST"
	}
}

// subjectNeedsGlob reports whether the template can only be expressed with a
// wildcard, which decides StringEquals versus StringLike.
func subjectNeedsGlob(sub string) bool { return hasGlob(sub) }

// trustPolicyFix builds the corrected Condition block for a federated door.
func trustPolicyFix(d *model.Door, p *model.ExternalParty) string {
	audKey := d.AudienceConditionKey()
	subKey := d.SubjectConditionKey()
	if subKey == "" {
		return ""
	}

	sub := subjectTemplate(d, p)
	b := newCond().eq(audKey, audienceFor(d))
	if subjectNeedsGlob(sub) {
		b.like(subKey, sub)
	} else {
		b.eq(subKey, sub)
	}
	return b.render()
}

// externalIDFix is the confused-deputy remedy for a cross-account trust.
func externalIDFix() string {
	return newCond().eq("sts:ExternalId", "A_SECRET_VALUE_THE_THIRD_PARTY_GENERATES_FOR_YOU").render()
}

func orDefault(s, fallback string) string {
	if s == "" || hasGlob(s) {
		return fallback
	}
	return s
}

func stripGlob(s string) string {
	if hasGlob(s) {
		return ""
	}
	return s
}

func hasGlob(s string) bool { return strings.ContainsAny(s, "*?") }
