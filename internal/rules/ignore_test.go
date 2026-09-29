package rules

import (
	"strings"
	"testing"
)

func TestParseIgnore(t *testing.T) {
	const file = `
# comments and blank lines are skipped

FD001  arn:aws:iam::111122223333:role/legacy-ci   # retiring 2026-10-01, OPS-42
FD013  *                                          # all partners use ExternalId
*      arn:aws:iam::111122223333:role/sandbox-*   # throwaway account
fd010  arn:aws:iam::111122223333:role/ci-deploy
`
	list, err := ParseIgnore(strings.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if list.Len() != 4 {
		t.Fatalf("parsed %d rules, want 4", list.Len())
	}

	cases := []struct {
		rule, arn string
		want      bool
		reason    string
	}{
		{"FD001", "arn:aws:iam::111122223333:role/legacy-ci", true, "retiring 2026-10-01, OPS-42"},
		{"FD002", "arn:aws:iam::111122223333:role/legacy-ci", false, ""},
		{"FD013", "arn:aws:iam::999988887777:role/anything", true, "all partners use ExternalId"},
		{"FD099", "arn:aws:iam::111122223333:role/sandbox-42", true, "throwaway account"},
		{"FD001", "arn:aws:iam::111122223333:role/sandbox", false, ""},
		{"FD010", "arn:aws:iam::111122223333:role/ci-deploy", true, ""}, // lowercase rule id matches
		{"FD001", "arn:aws:iam::111122223333:role/other", false, ""},
	}
	for _, c := range cases {
		reason, ok := list.Match(c.rule, c.arn)
		if ok != c.want {
			t.Errorf("Match(%s, %s) = %v, want %v", c.rule, c.arn, ok, c.want)
			continue
		}
		if c.reason != "" && reason != c.reason {
			t.Errorf("Match(%s, %s) reason = %q, want %q", c.rule, c.arn, reason, c.reason)
		}
	}
}

// A suppression with no stated reason still records that it was suppressed,
// and where - otherwise nobody can find out why six months later.
func TestIgnoreWithoutReasonStillExplainsItself(t *testing.T) {
	list, err := ParseIgnore(strings.NewReader("FD001 arn:aws:iam::1:role/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	reason, ok := list.Match("FD001", "arn:aws:iam::1:role/x")
	if !ok {
		t.Fatal("rule did not match")
	}
	if !strings.Contains(reason, "line 1") || !strings.Contains(reason, "no reason given") {
		t.Errorf("reason = %q, want it to point at the line and admit no reason was given", reason)
	}
}

func TestParseIgnoreRejectsMalformedLine(t *testing.T) {
	if _, err := ParseIgnore(strings.NewReader("FD001\n")); err == nil {
		t.Error("want an error for a line with no resource")
	} else if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error should name the line: %v", err)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"arn:aws:iam::1:role/ci", "arn:aws:iam::1:role/ci", true},
		{"arn:aws:iam::1:role/ci", "arn:aws:iam::1:role/cd", false},
		{"arn:aws:iam::1:role/*", "arn:aws:iam::1:role/ci", true},
		{"arn:aws:iam::1:role/*", "arn:aws:iam::2:role/ci", false},
		{"*role/ci", "arn:aws:iam::1:role/ci", true},
		{"*role/ci", "arn:aws:iam::1:role/cd", false},
		{"arn:*:role/ci", "arn:aws:iam::1:role/ci", true},
		{"arn:*:role/ci", "arn:aws:iam::1:role/cd", false},
		{"arn:*iam*role/ci", "arn:aws:iam::1:role/ci", true},
		{"ARN:AWS:IAM::1:ROLE/CI", "arn:aws:iam::1:role/ci", true}, // ARNs are matched case-insensitively
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// A prefix pattern must not match a string shorter than the prefix and suffix
// combined, which is the classic off-by-one in hand-rolled globbing.
func TestGlobMatchNoOverlap(t *testing.T) {
	if globMatch("abc*abc", "abc") {
		t.Error("globMatch let the prefix and suffix overlap")
	}
	if !globMatch("abc*abc", "abcXabc") {
		t.Error("globMatch rejected a valid prefix/suffix match")
	}
}
