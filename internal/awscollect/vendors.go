package awscollect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// A cross-account trust to 464622532012 is Datadog, not an intruder. Labelling
// the account ids we can identify keeps the report about the trusts that are
// actually unexplained.
//
// Accuracy matters here: a wrong label tells someone an unknown account is a
// vendor. So every entry carries the vendor doc it came from, the label is
// informational only (it never suppresses a finding by itself), and the map is
// extendable at runtime with --vendors.

// Vendor is a SaaS provider that asks customers for a cross-account role.
type Vendor struct {
	Name   string `json:"name"`
	Source string `json:"source"` // vendor doc that publishes this account id
	Note   string `json:"note,omitempty"`
}

// vendorAccounts maps an AWS account id to the vendor that owns it.
//
// TO ADD AN ENTRY: paste the account id from the vendor's own published
// CloudFormation template or docs page and put that URL in Source. Do not add
// an id you cannot cite - an unverified label is worse than no label.
// Verified 2026-09-30 against the sources below. Datadog uses a different
// account per site, and its docs page substitutes the id from a site selector
// rather than listing them, so the citations here are the CloudFormation
// template and the Terraform guide, which carry the ids as static text. The
// site each Datadog id serves is deliberately not claimed: what the label is
// for is "this is Datadog, not a stranger", and that holds without it.
var vendorAccounts = map[string]Vendor{
	"464622532012": {
		Name:   "Datadog",
		Source: "https://github.com/DataDog/cloudformation-template/blob/master/aws/datadog_integration_role.yaml",
		Note:   "DdAWSAccountId in Datadog's own integration-role template",
	},
	"417141415827": {
		Name:   "Datadog",
		Source: "https://docs.datadoghq.com/integrations/guide/aws-terraform-setup/",
	},
	"669783387624": {
		Name:   "Datadog",
		Source: "https://docs.datadoghq.com/integrations/guide/aws-terraform-setup/",
	},
	"392588925713": {
		Name:   "Datadog",
		Source: "https://docs.datadoghq.com/integrations/guide/aws-terraform-setup/",
	},
	"754728514883": {
		Name:   "New Relic",
		Source: "https://docs.newrelic.com/docs/infrastructure/amazon-integrations/connect/connect-aws-new-relic-infrastructure-monitoring/",
		Note:   "cloud integrations; workflow automation uses a different account",
	},
	"253490767857": {
		Name:   "New Relic (workflow automation)",
		Source: "https://docs.newrelic.com/docs/workflow-automation/setup-and-configure/set-up-aws-credentials/iam-role-setup/",
	},
	"926226587429": {
		Name:   "Sumo Logic",
		Source: "https://www.sumologic.com/help/docs/send-data/hosted-collectors/amazon-aws/grant-access-aws-product/",
	},
}

// vendorNameHints catch vendors that do not publish one fixed account id -
// Wiz, Orca and Snyk provision per-tenant accounts, so no static map can cover
// them. Matching on the role name is a hint for the reader, never proof, and
// is reported with "possibly" wording.
var vendorNameHints = map[string]string{
	"wiz":         "Wiz",
	"orca":        "Orca Security",
	"snyk":        "Snyk",
	"datadog":     "Datadog",
	"newrelic":    "New Relic",
	"sumologic":   "Sumo Logic",
	"lacework":    "Lacework",
	"cloudhealth": "CloudHealth",
	"prismacloud": "Prisma Cloud",
	"dome9":       "Check Point CloudGuard",
	"vanta":       "Vanta",
	"drata":       "Drata",
	"secorvia":    "Secorvia",
}

// lookupVendor resolves an account id to a known vendor.
func lookupVendor(accountID string) (Vendor, bool) {
	v, ok := vendorAccounts[accountID]
	return v, ok
}

// hintVendor guesses from a role name or path. The caller must present this
// as a guess.
func hintVendor(names ...string) string {
	for _, n := range names {
		lower := strings.ToLower(strings.ReplaceAll(n, "-", ""))
		lower = strings.ReplaceAll(lower, "_", "")
		for key, vendor := range vendorNameHints {
			if strings.Contains(lower, key) {
				return vendor
			}
		}
	}
	return ""
}

// LoadVendorFile merges extra account-id -> vendor entries from a JSON file,
// so an organization can label its own partner accounts without a fork.
//
//	{ "111122223333": { "name": "Acme MSP", "source": "internal ticket OPS-42" } }
func LoadVendorFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read vendor file: %w", err)
	}
	var extra map[string]Vendor
	if err := json.Unmarshal(b, &extra); err != nil {
		return fmt.Errorf("parse vendor file %s: %w", path, err)
	}
	for id, v := range extra {
		if v.Name == "" {
			return fmt.Errorf("vendor file %s: entry %s has no name", path, id)
		}
		vendorAccounts[id] = v
	}
	return nil
}
