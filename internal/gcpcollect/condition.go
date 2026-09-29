package gcpcollect

import (
	"regexp"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// A workload identity provider's attributeCondition is a CEL expression:
//
//	assertion.repository_owner == 'acme'
//	attribute.repository in ['acme/api', 'acme/web']
//	assertion.sub.startsWith('repo:acme/')
//
// Parsing CEL properly would mean shipping a CEL engine. What the rules
// actually need is narrower: does this expression constrain the subject at
// all, and if so, on what. So this file extracts the constraints it can
// recognise and is explicit when it cannot - the raw expression is always in
// the output so a reader can check.

var (
	// assertion.foo == 'bar'  /  attribute.foo != "bar"
	reCompare = regexp.MustCompile(`\b((?:assertion|attribute)(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*(==|!=)\s*['"]([^'"]*)['"]`)
	// assertion.foo in ['a', 'b']
	reIn = regexp.MustCompile(`\b((?:assertion|attribute)(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s+in\s+\[([^\]]*)\]`)
	// assertion.foo.startsWith('bar')  /  .endsWith  /  .contains  /  .matches
	reMethod = regexp.MustCompile(`\b((?:assertion|attribute)(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\.(startsWith|endsWith|contains|matches)\(\s*['"]([^'"]*)['"]\s*\)`)
	// bare literals in a list
	reLiteral = regexp.MustCompile(`['"]([^'"]*)['"]`)
)

// ParseAttributeCondition turns a CEL expression into the conditions it
// recognises. An expression that yields nothing is reported as nothing, not
// as "no constraint" - the caller decides what an empty result means.
func ParseAttributeCondition(cel string) []model.Condition {
	cel = strings.TrimSpace(cel)
	if cel == "" {
		return nil
	}

	var out []model.Condition
	seen := map[string]bool{}
	add := func(op, key string, values ...string) {
		sig := op + "\x00" + key + "\x00" + strings.Join(values, ",")
		if seen[sig] {
			return
		}
		seen[sig] = true
		out = append(out, model.Condition{Operator: op, Key: key, Values: values})
	}

	for _, m := range reCompare.FindAllStringSubmatch(cel, -1) {
		op := "equals"
		if m[2] == "!=" {
			op = "notEquals"
		}
		add(op, m[1], m[3])
	}
	for _, m := range reIn.FindAllStringSubmatch(cel, -1) {
		var values []string
		for _, lit := range reLiteral.FindAllStringSubmatch(m[2], -1) {
			values = append(values, lit[1])
		}
		if len(values) > 0 {
			add("in", m[1], values...)
		}
	}
	for _, m := range reMethod.FindAllStringSubmatch(cel, -1) {
		add(m[2], m[1], m[3])
	}
	return out
}

// subjectKeys are the CEL identifiers that actually pin down who is calling.
// A condition on assertion.aud or on a timestamp is a condition, but it is not
// a constraint on the caller, and treating it as one would hide an open door.
var subjectKeys = map[string]bool{
	"assertion.sub":              true,
	"assertion.repository":       true,
	"assertion.repository_id":    true,
	"assertion.repository_owner": true,
	"assertion.project_path":     true,
	"assertion.namespace_path":   true,
	"assertion.workflow":         true,
	"assertion.job_workflow_ref": true,
	"assertion.ref":              true,
	"assertion.environment":      true,
	"assertion.actor":            true,
	"assertion.arn":              true,
	"assertion.account":          true,
	"attribute.subject":          true,
	"attribute.repository":       true,
	"attribute.repository_owner": true,
	"attribute.project_path":     true,
	"attribute.aws_role":         true,
	"attribute.aws_account":      true,
	"attribute.ref":              true,
	"attribute.environment":      true,
	"attribute.google.subject":   true,
}

// ConstrainsSubject reports whether the expression narrows WHO may use the
// provider, and returns the keys it recognised.
//
// A negative answer is only trustworthy for expressions we can read. When
// there is text we could not parse at all, the second return is false and the
// caller must say "could not determine" rather than "wide open".
func ConstrainsSubject(cel string) (constrained bool, understood bool, keys []string) {
	cel = strings.TrimSpace(cel)
	if cel == "" {
		// No expression is not an unparseable expression: we understand it
		// perfectly, and it constrains nothing.
		return false, true, nil
	}

	conds := ParseAttributeCondition(cel)
	for _, c := range conds {
		if c.Operator == "notEquals" {
			// An exclusion is not an inclusion.
			continue
		}
		key := strings.ToLower(c.Key)
		if subjectKeys[key] || strings.HasPrefix(key, "attribute.") && key != "attribute.aud" {
			constrained = true
			keys = append(keys, c.Key)
		}
	}
	// If we recognised nothing at all in a non-empty expression, we do not
	// know what it does.
	return constrained, len(conds) > 0, keys
}
