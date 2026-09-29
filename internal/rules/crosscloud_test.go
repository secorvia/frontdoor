package rules

import (
	"strings"
	"testing"

	"github.com/secorvia/frontdoor/internal/model"
)

// The scenario this whole project exists for:
//
//	github.com/acme/api  --OIDC-->  AWS role/ci-deploy   (looks fine)
//	AWS role/ci-deploy   --WIF-->   GCP data-pipeline@   (BigQuery)
//
// The AWS scanner stops at the role. The GCP scanner sees a workload identity
// binding from "some AWS role" and has no idea a public CI platform is on the
// other end of it. Neither reports the path. Both are correct about their half.

const (
	ciRoleARN  = "arn:aws:iam::111122223333:role/ci-deploy"
	pipelineSA = "data-pipeline@acme-prod.iam.gserviceaccount.com"
	awsPool    = "projects/999/locations/global/workloadIdentityPools/aws-prod"
)

// crossCloudFixture builds the two halves two separate scans would produce.
func crossCloudFixture() *model.Result {
	githubParty := model.ExternalParty{
		Kind: model.PartyGitHub, Scope: model.ScopeExact,
		Display: "github.com/acme/api @ refs/heads/main",
		Org:     "acme", Project: "api", Ref: "refs/heads/main",
	}

	// The AWS half: a GitHub repository can assume a role that, on its own,
	// holds nothing interesting.
	awsDoor := model.Door{
		Provider: model.ProviderAWS, AccountID: "111122223333",
		ResourceARN: ciRoleARN, ResourceName: "ci-deploy", NodeID: ciRoleARN,
		PrincipalType:   model.PrincipalOIDC,
		Issuer:          "token.actions.githubusercontent.com",
		TrustActions:    []string{"sts:AssumeRoleWithWebIdentity"},
		ExternalParties: []model.ExternalParty{githubParty},
		Conditions: []model.Condition{
			{Operator: "StringEquals", Key: "token.actions.githubusercontent.com:aud", Values: []string{"sts.amazonaws.com"}},
			{Operator: "StringEquals", Key: "token.actions.githubusercontent.com:sub", Values: []string{"repo:acme/api:ref:refs/heads/main"}},
		},
		GrantedActions: []string{"ecr:GetAuthorizationToken"},
	}

	// The GCP half: a workload identity binding admitting that AWS role. To the
	// GCP collector this is just "an AWS caller".
	gcpDoor := model.Door{
		Provider: model.ProviderGCP, AccountID: "acme-prod",
		ResourceARN:  "projects/acme-prod/serviceAccounts/" + pipelineSA,
		ResourceName: pipelineSA, NodeID: pipelineSA,
		PrincipalType: model.PrincipalCrossAccount,
		ProviderARN:   awsPool + "/providers/aws",
		Issuer:        "AWS account 111122223333",
		TrustActions:  []string{"roles/iam.workloadIdentityUser"},
		ExternalParties: []model.ExternalParty{{
			Kind: model.PartyAWSAccount, Scope: model.ScopeExact,
			Display:   "AWS role ci-deploy in account 111122223333",
			AccountID: "111122223333",
			Subject:   "principal://iam.googleapis.com/" + awsPool + "/subject/arn:aws:sts::111122223333:assumed-role/ci-deploy/session",
			NodeRef:   ciRoleARN,
		}},
		GrantedActions: []string{"roles/bigquery.dataViewer"},
	}

	return &model.Result{
		Accounts: []model.Account{
			{Provider: model.ProviderAWS, ID: "111122223333", Scanned: true},
			{Provider: model.ProviderGCP, ID: "acme-prod", Scanned: true},
		},
		Doors: []model.Door{awsDoor, gcpDoor},
		Principals: []model.Principal{
			{Provider: model.ProviderAWS, NodeID: ciRoleARN, Name: "ci-deploy",
				AccountID: "111122223333", Grants: []string{"ecr:GetAuthorizationToken"}},
			{Provider: model.ProviderGCP, NodeID: pipelineSA, Name: pipelineSA,
				AccountID: "acme-prod", UniqueID: "109876543210987654321",
				Grants: []string{"roles/bigquery.dataViewer"}},
		},
	}
}

func TestDeriveCrossCloudEdges(t *testing.T) {
	res := crossCloudFixture()
	edges, internal := DeriveCrossCloudEdges(res)

	if len(edges) != 1 {
		t.Fatalf("want 1 cross-cloud edge, got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.From != ciRoleARN {
		t.Errorf("From = %q, want the AWS role ARN", e.From)
	}
	if e.To != pipelineSA {
		t.Errorf("To = %q, want the GCP service account", e.To)
	}
	if e.FromProvider != model.ProviderAWS || e.Provider != model.ProviderGCP {
		t.Errorf("edge providers = %q -> %q, want aws -> gcp", e.FromProvider, e.Provider)
	}
	if len(internal) != 1 {
		t.Errorf("the AWS role should be marked an internal seam, not an entry point: %v", internal)
	}
}

// The headline: one chain, two clouds, ending at a data store.
func TestCrossCloudChain(t *testing.T) {
	res := crossCloudFixture()
	Run(res, Options{Now: testNow})

	var cross *model.Chain
	for i := range res.Chains {
		if res.Chains[i].CrossCloud() {
			cross = &res.Chains[i]
		}
	}
	if cross == nil {
		t.Fatalf("no cross-cloud chain found; chains = %d", len(res.Chains))
	}

	if cross.Entry.Display != "github.com/acme/api @ refs/heads/main" {
		t.Errorf("Entry = %q, want the GitHub repository, not the AWS role", cross.Entry.Display)
	}
	if cross.Terminal != pipelineSA {
		t.Errorf("Terminal = %q, want the GCP service account", cross.Terminal)
	}
	if cross.Length() != 2 {
		t.Errorf("Length = %d, want 2 (federation into AWS, then AWS into GCP)", cross.Length())
	}

	wantClouds := []model.Provider{model.ProviderAWS, model.ProviderGCP}
	if len(cross.Clouds) != 2 || cross.Clouds[0] != wantClouds[0] || cross.Clouds[1] != wantClouds[1] {
		t.Errorf("Clouds = %v, want %v", cross.Clouds, wantClouds)
	}

	// The terminal is not privileged - it is worse than that in a way a
	// privilege check would miss entirely. It holds data.
	if cross.TerminalPrivileged {
		t.Error("the terminal was marked privileged; roles/bigquery.dataViewer is not an escalation")
	}
	if cross.TerminalSensitivity != model.SensitivityData {
		t.Errorf("TerminalSensitivity = %q, want data", cross.TerminalSensitivity)
	}
	if len(cross.TerminalReach) == 0 || !strings.Contains(cross.TerminalReach[0], "BigQuery") {
		t.Errorf("TerminalReach = %v, want it to name BigQuery", cross.TerminalReach)
	}
}

func TestFD031(t *testing.T) {
	res := crossCloudFixture()
	Run(res, Options{Now: testNow})

	var f *model.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "FD031" {
			f = &res.Findings[i]
		}
	}
	if f == nil {
		t.Fatalf("FD031 did not fire; findings = %v", ids(run(crossCloudFixture())))
	}

	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %q, want critical for a chain that ends at a data store", f.Severity)
	}
	if !strings.Contains(f.Title, "BigQuery") {
		t.Errorf("Title does not name what is reached: %q", f.Title)
	}
	if !strings.Contains(f.WhatIsWrong, "AWS") || !strings.Contains(f.WhatIsWrong, "GCP") {
		t.Errorf("WhatIsWrong does not name both clouds: %q", f.WhatIsWrong)
	}
	// The point of the finding is that neither single-cloud scanner sees it.
	if !strings.Contains(f.WhatIsWrong, "scanner") {
		t.Errorf("WhatIsWrong does not explain why this goes unreported: %q", f.WhatIsWrong)
	}
	if !strings.Contains(strings.Join(f.Fix.Steps, " "), "crossing happens at") {
		t.Errorf("the fix does not name the crossing point: %v", f.Fix.Steps)
	}

	evidence := strings.Join(f.Evidence, " | ")
	if !strings.Contains(evidence, "aws -> gcp") {
		t.Errorf("evidence does not mark the cloud boundary: %s", evidence)
	}
}

// An AWS role federating from a GCP service account is the same seam in the
// other direction, and the join has to work on the numeric unique id because
// that is all the AWS trust policy carries.
func TestCrossCloudGoogleIntoAWS(t *testing.T) {
	const uniqueID = "109876543210987654321"

	res := &model.Result{
		Accounts: []model.Account{
			{Provider: model.ProviderAWS, ID: "111122223333", Scanned: true},
			{Provider: model.ProviderGCP, ID: "acme-prod", Scanned: true},
		},
		Doors: []model.Door{
			// GCP: a GitHub repo can become the pipeline service account.
			{
				Provider: model.ProviderGCP, AccountID: "acme-prod",
				ResourceARN:  "projects/acme-prod/serviceAccounts/" + pipelineSA,
				ResourceName: pipelineSA, NodeID: pipelineSA,
				PrincipalType: model.PrincipalOIDC,
				TrustActions:  []string{"roles/iam.workloadIdentityUser"},
				ExternalParties: []model.ExternalParty{{
					Kind: model.PartyGitHub, Scope: model.ScopeExact,
					Display: "github.com/acme/api @ refs/heads/main",
				}},
			},
			// AWS: a role trusting that service account, by its numeric id.
			{
				Provider: model.ProviderAWS, AccountID: "111122223333",
				ResourceARN: ciRoleARN, ResourceName: "ci-deploy", NodeID: ciRoleARN,
				PrincipalType: model.PrincipalOIDC,
				Issuer:        "accounts.google.com",
				TrustActions:  []string{"sts:AssumeRoleWithWebIdentity"},
				ExternalParties: []model.ExternalParty{{
					Kind: model.PartyGoogle, Scope: model.ScopeExact,
					Display: "GCP service account (unique id " + uniqueID + ")",
					Actor:   uniqueID,
				}},
				GrantedActions:   []string{"iam:PassRole"},
				IsPrivileged:     true,
				PrivilegeReasons: []string{"grants iam:PassRole: can pass any role to a service"},
			},
		},
		Principals: []model.Principal{
			{Provider: model.ProviderGCP, NodeID: pipelineSA, UniqueID: uniqueID, AccountID: "acme-prod"},
			{Provider: model.ProviderAWS, NodeID: ciRoleARN, AccountID: "111122223333",
				Grants: []string{"iam:PassRole"}, Privileged: true,
				Reasons: []string{"grants iam:PassRole: can pass any role to a service"}},
		},
	}

	Run(res, Options{Now: testNow})

	var cross *model.Chain
	for i := range res.Chains {
		if res.Chains[i].CrossCloud() {
			cross = &res.Chains[i]
		}
	}
	if cross == nil {
		t.Fatalf("no cross-cloud chain found; chains = %d", len(res.Chains))
	}
	if cross.Terminal != ciRoleARN {
		t.Errorf("Terminal = %q, want the AWS role", cross.Terminal)
	}
	if !cross.TerminalPrivileged {
		t.Error("the AWS role holds iam:PassRole and should be marked privileged")
	}
	if cross.Clouds[0] != model.ProviderGCP || cross.Clouds[1] != model.ProviderAWS {
		t.Errorf("Clouds = %v, want gcp then aws", cross.Clouds)
	}
}

// An AWS account we were never pointed at is genuinely outside. Drawing an
// edge into it would invent a node we know nothing about, so the door stays an
// entry point.
func TestUnscannedCloudStaysAnEntryPoint(t *testing.T) {
	res := crossCloudFixture()
	// Forget the AWS side entirely, as though only GCP had been scanned.
	res.Doors = res.Doors[1:]
	res.Principals = res.Principals[1:]
	res.Accounts = res.Accounts[1:]

	edges, internal := DeriveCrossCloudEdges(res)
	if len(edges) != 0 {
		t.Errorf("an edge was drawn to an unscanned AWS role: %+v", edges)
	}
	if len(internal) != 0 {
		t.Errorf("the door was marked internal despite the other side being unknown: %v", internal)
	}

	Run(res, Options{Now: testNow})
	for _, c := range res.Chains {
		if c.CrossCloud() {
			t.Errorf("a cross-cloud chain was built with only one cloud scanned: %s", c.ShortPath())
		}
	}
}

// Cross-cloud chains outrank single-cloud ones at equal entry and terminal
// weight, because they are the ones nothing else is looking at.
func TestCrossCloudOutranks(t *testing.T) {
	single := model.Chain{
		Entry:               model.ExternalParty{Scope: model.ScopeExact},
		Hops:                []model.Hop{{}, {}},
		TerminalSensitivity: model.SensitivityData,
		Clouds:              []model.Provider{model.ProviderAWS},
	}
	cross := single
	cross.Clouds = []model.Provider{model.ProviderAWS, model.ProviderGCP}

	if cross.Risk() <= single.Risk() {
		t.Errorf("cross-cloud risk %d should beat single-cloud risk %d",
			cross.Risk(), single.Risk())
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		provider   model.Provider
		grants     []string
		privileged bool
		want       model.Sensitivity
		reach      string
	}{
		{"aws data action", model.ProviderAWS, []string{"s3:GetObject"}, false, model.SensitivityData, "S3 objects"},
		{"aws service wildcard", model.ProviderAWS, []string{"dynamodb:*"}, false, model.SensitivityData, "DynamoDB"},
		{"aws describe only", model.ProviderAWS, []string{"ec2:DescribeInstances"}, false, model.SensitivityLow, ""},
		{"aws star", model.ProviderAWS, []string{"*"}, false, model.SensitivityAdmin, "everything"},
		{"aws privileged flag wins", model.ProviderAWS, []string{"s3:GetObject"}, true, model.SensitivityAdmin, "S3 objects"},
		{"gcp bigquery", model.ProviderGCP, []string{"roles/bigquery.dataViewer"}, false, model.SensitivityData, "BigQuery"},
		{"gcp compute", model.ProviderGCP, []string{"roles/run.admin"}, false, model.SensitivityCompute, "Cloud Run"},
		{"gcp viewer", model.ProviderGCP, []string{"roles/viewer"}, false, model.SensitivityLow, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reach := Classify(c.provider, c.grants, c.privileged)
			if got != c.want {
				t.Errorf("Sensitivity = %q, want %q", got, c.want)
			}
			if c.reach == "" {
				return
			}
			if !strings.Contains(strings.Join(reach, " "), c.reach) {
				t.Errorf("Reach = %v, want it to mention %q", reach, c.reach)
			}
		})
	}
}

// An unrecognised permission must contribute nothing rather than be guessed
// into a category: naming the wrong data store is worse than naming none.
func TestClassifySaysNothingItCannotKnow(t *testing.T) {
	got, reach := Classify(model.ProviderAWS, []string{"acme:DoTheThing", "weird:Action"}, false)
	if got != model.SensitivityLow {
		t.Errorf("Sensitivity = %q, want low for permissions we do not recognise", got)
	}
	if len(reach) != 0 {
		t.Errorf("Reach = %v, want empty", reach)
	}
}
