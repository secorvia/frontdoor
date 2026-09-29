package rules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// IgnoreList suppresses findings the team has decided about. Suppressed
// findings stay in the output marked as suppressed rather than disappearing:
// a finding you cannot see is one nobody re-examines when the reason expires.
type IgnoreList struct {
	rules []ignoreRule
	Path  string
}

type ignoreRule struct {
	RuleID   string // FD001, or * for any
	Resource string // ARN, optionally with a leading or trailing *, or * for any
	Reason   string
	Line     int
}

// ParseIgnoreFile reads a .frontdoorignore.
//
//	# one rule per line: RULE_ID  RESOURCE  # reason
//	FD001  arn:aws:iam::111122223333:role/legacy-ci   # retiring 2026-10-01, ticket OPS-42
//	FD013  *                                          # all partners use ExternalId via our portal
//	*      arn:aws:iam::111122223333:role/sandbox-*   # throwaway sandbox account
func ParseIgnoreFile(path string) (*IgnoreList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read ignore file: %w", err)
	}
	defer f.Close()

	list, err := ParseIgnore(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	list.Path = path
	return list, nil
}

// ParseIgnore reads ignore rules from any source.
func ParseIgnore(r io.Reader) (*IgnoreList, error) {
	list := &IgnoreList{}
	scanner := bufio.NewScanner(r)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		reason := ""
		if body, comment, ok := strings.Cut(line, "#"); ok {
			line = strings.TrimSpace(body)
			reason = strings.TrimSpace(comment)
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want RULE_ID and RESOURCE, got %q", lineNo, line)
		}
		list.rules = append(list.rules, ignoreRule{
			RuleID:   strings.ToUpper(fields[0]),
			Resource: fields[1],
			Reason:   reason,
			Line:     lineNo,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// Match reports whether a finding is suppressed, and why.
func (l *IgnoreList) Match(ruleID, resourceARN string) (string, bool) {
	if l == nil {
		return "", false
	}
	for _, r := range l.rules {
		if r.RuleID != "*" && !strings.EqualFold(r.RuleID, ruleID) {
			continue
		}
		if !globMatch(r.Resource, resourceARN) {
			continue
		}
		reason := r.Reason
		if reason == "" {
			reason = fmt.Sprintf("suppressed by %s line %d (no reason given)", orDefault(l.Path, "ignore file"), r.Line)
		}
		return reason, true
	}
	return "", false
}

// Len is how many rules were loaded, for the summary line.
func (l *IgnoreList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.rules)
}

// globMatch supports a leading and/or trailing * on the resource pattern,
// which covers path prefixes and account wildcards without pulling in a
// regex the user then has to debug.
func globMatch(pattern, s string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	star := strings.Count(pattern, "*")
	if star == 0 {
		return strings.EqualFold(pattern, s)
	}

	pre, post, _ := strings.Cut(pattern, "*")
	if star == 1 {
		switch {
		case pre == "":
			return hasSuffixFold(s, post)
		case post == "":
			return hasPrefixFold(s, pre)
		default:
			return hasPrefixFold(s, pre) && hasSuffixFold(s, post) && len(s) >= len(pre)+len(post)
		}
	}

	// More than one star: match each literal segment in order.
	segments := strings.Split(pattern, "*")
	rest := s
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if i == 0 {
			if !hasPrefixFold(rest, seg) {
				return false
			}
			rest = rest[len(seg):]
			continue
		}
		idx := strings.Index(strings.ToLower(rest), strings.ToLower(seg))
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(seg):]
	}
	if last := segments[len(segments)-1]; last != "" {
		return hasSuffixFold(s, last)
	}
	return true
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}
