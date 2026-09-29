package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// SARIF is how findings reach the GitHub Security tab. GitHub is strict about
// a few things and silent when they are wrong, so this file is deliberately
// explicit: every result needs a location, every rule needs a security-severity
// property to get a severity in the UI, and fingerprints have to be stable or
// every run opens fresh alerts and closes yesterday's.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolURI      = "https://github.com/secorvia/frontdoor"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifHelp      `json:"help"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Precision        string   `json:"precision,omitempty"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]string  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
	Message          *sarifText    `json:"message,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// SARIF writes a SARIF 2.1.0 log.
func SARIF(w io.Writer, res *model.Result) error {
	rules, index := sarifRules(res)

	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		r := sarifResult{
			RuleID:    f.ID,
			RuleIndex: index[f.ID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: sarifMessage(f)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					// Cloud findings have no file. GitHub still requires a
					// location, so the ARN becomes a stable synthetic path -
					// it is what a reader would search for anyway.
					ArtifactLocation: sarifArtifact{URI: arnToURI(f.ResourceARN)},
					Region:           &sarifRegion{StartLine: 1},
				},
				Message: &sarifText{Text: f.ResourceARN},
			}},
			PartialFingerprints: map[string]string{
				"frontdoor/v1": fingerprint(f),
			},
		}
		props := map[string]string{}
		if f.AccountID != "" {
			props["accountId"] = f.AccountID
		}
		if f.Issuer != "" {
			props["issuer"] = f.Issuer
		}
		if f.ExternalParty != "" {
			props["externalParty"] = f.ExternalParty
		}
		if len(props) > 0 {
			r.Properties = props
		}
		if f.Suppressed {
			r.Suppressions = []sarifSuppression{{
				Kind:          "external",
				Justification: orPlaceholder(f.SuppressReason, "suppressed by .frontdoorignore"),
			}}
		}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "frontdoor",
				Version:         res.Version,
				SemanticVersion: res.Version,
				InformationURI:  toolURI,
				Rules:           rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// sarifRules builds one rule entry per distinct rule id actually present, in a
// stable order, plus the id -> index map results refer to.
func sarifRules(res *model.Result) ([]sarifRule, map[string]int) {
	seen := map[string]model.Finding{}
	for _, f := range res.Findings {
		if _, ok := seen[f.ID]; !ok {
			seen[f.ID] = f
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		f := seen[id]
		index[id] = i
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             ruleName(id, f.Title),
			ShortDescription: sarifText{Text: ruleShort(f)},
			FullDescription:  sarifText{Text: f.WhatIsWrong},
			Help: sarifHelp{
				Text:     helpText(f),
				Markdown: helpMarkdown(f),
			},
			HelpURI: f.DocsURL,
			Properties: sarifRuleProps{
				Tags:             []string{"security", "cloud", "iam", "federation", string(f.Provider)},
				SecuritySeverity: securitySeverity(f.Severity),
				Precision:        "high",
			},
		})
	}
	return rules, index
}

// ruleName must be a readable identifier, not a sentence. GitHub shows it in
// the alert list next to the id.
func ruleName(id, title string) string {
	name := title
	if i := strings.Index(name, ":"); i > 0 && i < 60 {
		name = name[:i]
	}
	name = strings.Join(strings.Fields(name), "")
	if name == "" {
		return id
	}
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

func ruleShort(f model.Finding) string {
	if f.WhatIsWrong == "" {
		return f.Title
	}
	if i := strings.Index(f.WhatIsWrong, ". "); i > 0 {
		return f.WhatIsWrong[:i+1]
	}
	return f.WhatIsWrong
}

func helpText(f model.Finding) string {
	var b strings.Builder
	b.WriteString(f.WhatIsWrong)
	if f.AttackerCan != "" {
		b.WriteString("\n\nWhat an attacker could do: " + f.AttackerCan)
	}
	if f.Fix.Summary != "" {
		b.WriteString("\n\nFix: " + f.Fix.Summary)
	}
	for _, s := range f.Fix.Steps {
		b.WriteString("\n  - " + s)
	}
	if f.Fix.TrustPolicy != "" {
		b.WriteString("\n\n" + f.Fix.TrustPolicy)
	}
	return b.String()
}

func helpMarkdown(f model.Finding) string {
	var b strings.Builder
	b.WriteString("**" + f.WhatIsWrong + "**\n")
	if f.AttackerCan != "" {
		b.WriteString("\n_What an attacker could do:_ " + f.AttackerCan + "\n")
	}
	if f.Fix.Summary != "" {
		b.WriteString("\n### Fix\n\n" + f.Fix.Summary + "\n")
	}
	for _, s := range f.Fix.Steps {
		b.WriteString("\n- " + s)
	}
	if f.Fix.TrustPolicy != "" {
		b.WriteString("\n\n```json\n" + f.Fix.TrustPolicy + "\n```\n")
	}
	if f.DocsURL != "" {
		b.WriteString("\n[Full explanation](" + f.DocsURL + ")\n")
	}
	return b.String()
}

func sarifMessage(f model.Finding) string {
	msg := f.Title
	if f.WhatIsWrong != "" {
		msg += " " + f.WhatIsWrong
	}
	if f.AttackerCan != "" {
		msg += " An attacker could: " + f.AttackerCan
	}
	return msg
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the CVSS-like number GitHub reads to bucket an alert.
// Critical >= 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9.
func securitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "7.5"
	case model.SeverityMedium:
		return "5.0"
	case model.SeverityLow:
		return "2.0"
	default:
		return "0.0"
	}
}

// arnToURI turns arn:aws:iam::111122223333:role/ci-deploy into
// aws/111122223333/iam/role/ci-deploy, which sorts and reads like a path.
func arnToURI(arn string) string {
	if arn == "" {
		return "cloud/unknown"
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return "cloud/" + strings.ReplaceAll(arn, ":", "/")
	}
	partition, service, account, resource := parts[1], parts[2], parts[4], parts[5]
	segments := []string{partition, account, service, resource}

	var out []string
	for _, s := range segments {
		if s != "" {
			out = append(out, strings.ReplaceAll(s, ":", "/"))
		}
	}
	return strings.Join(out, "/")
}

// fingerprint identifies the same finding across runs so GitHub updates an
// alert instead of opening a new one. It must not include anything that
// changes between scans - no timestamps, no counts.
func fingerprint(f model.Finding) string {
	sum := sha256.Sum256([]byte(f.ID + "\x00" + f.ResourceARN + "\x00" + f.ExternalParty))
	return hex.EncodeToString(sum[:16])
}

func orPlaceholder(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
