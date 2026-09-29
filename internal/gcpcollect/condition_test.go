package gcpcollect

import (
	"strings"
	"testing"
)

func TestParseAttributeCondition(t *testing.T) {
	tests := []struct {
		name string
		cel  string
		want []string // "operator key=values"
	}{
		{
			name: "simple equality",
			cel:  "assertion.repository_owner == 'acme'",
			want: []string{"equals assertion.repository_owner=acme"},
		},
		{
			name: "double quotes",
			cel:  `attribute.repository == "acme/api"`,
			want: []string{"equals attribute.repository=acme/api"},
		},
		{
			name: "membership",
			cel:  "attribute.repository in ['acme/api', 'acme/web']",
			want: []string{"in attribute.repository=acme/api,acme/web"},
		},
		{
			name: "startsWith",
			cel:  "assertion.sub.startsWith('repo:acme/')",
			want: []string{"startsWith assertion.sub=repo:acme/"},
		},
		{
			name: "conjunction keeps both",
			cel:  "assertion.repository_owner == 'acme' && assertion.ref == 'refs/heads/main'",
			want: []string{
				"equals assertion.repository_owner=acme",
				"equals assertion.ref=refs/heads/main",
			},
		},
		{
			name: "negation is recorded as such",
			cel:  "assertion.repository != 'acme/forbidden'",
			want: []string{"notEquals assertion.repository=acme/forbidden"},
		},
		{
			name: "empty",
			cel:  "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseAttributeCondition(tt.cel)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d conditions %v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i, c := range got {
				repr := c.Operator + " " + c.Key + "=" + strings.Join(c.Values, ",")
				if repr != tt.want[i] {
					t.Errorf("condition %d = %q, want %q", i, repr, tt.want[i])
				}
			}
		})
	}
}

// The whole point of reading the condition is to answer one question: does it
// narrow WHO is calling? A condition on the audience or on a timestamp does
// not, and treating it as if it did would hide an open door.
func TestConstrainsSubject(t *testing.T) {
	tests := []struct {
		name        string
		cel         string
		constrained bool
		understood  bool
	}{
		{"empty is understood and constrains nothing", "", false, true},
		{"owner", "assertion.repository_owner == 'acme'", true, true},
		{"repository", "attribute.repository == 'acme/api'", true, true},
		{"subject prefix", "assertion.sub.startsWith('repo:acme/')", true, true},
		{"membership list", "attribute.repository in ['acme/api']", true, true},
		{"audience alone does not say who", "assertion.aud == 'sts.googleapis.com'", false, true},
		{
			name: "negation alone is an exclusion, not an inclusion",
			cel:  "assertion.repository != 'acme/forbidden'", constrained: false, understood: true,
		},
		{
			name:        "an expression we cannot read is reported as unread, not as open",
			cel:         "has(assertion.enterprise) && assertion.enterprise.size() > 0",
			constrained: false, understood: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constrained, understood, _ := ConstrainsSubject(tt.cel)
			if constrained != tt.constrained {
				t.Errorf("constrained = %v, want %v", constrained, tt.constrained)
			}
			if understood != tt.understood {
				t.Errorf("understood = %v, want %v", understood, tt.understood)
			}
		})
	}
}

func TestConstrainsSubjectNamesTheKeys(t *testing.T) {
	_, _, keys := ConstrainsSubject("assertion.repository_owner == 'acme' && assertion.ref == 'refs/heads/main'")
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want both recognised keys", keys)
	}
}
