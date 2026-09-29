package awscollect

import "testing"

func TestClassifyAction(t *testing.T) {
	privileged := []string{
		"*",
		"*:*",
		"iam:*",
		"IAM:PassRole",
		"iam:passrole",
		"sts:*",
		"organizations:*",
		"iam:CreateAccessKey",
		"iam:UpdateAssumeRolePolicy",
		"lambda:UpdateFunctionCode",
		"iam:Put*",
		"ssm:SendCommand",
	}
	for _, a := range privileged {
		if _, ok := classifyAction(a); !ok {
			t.Errorf("classifyAction(%q) = not privileged, want privileged", a)
		}
	}

	benign := []string{
		"s3:GetObject",
		"ec2:DescribeInstances",
		"logs:PutLogEvents",
		"cloudwatch:GetMetricData",
		"s3:*",
	}
	for _, a := range benign {
		if reason, ok := classifyAction(a); ok {
			t.Errorf("classifyAction(%q) = privileged (%s), want not privileged", a, reason)
		}
	}
}

func TestAnalyzeGrants(t *testing.T) {
	doc, err := parsePolicyDocument(`{
	  "Version":"2012-10-17",
	  "Statement":[
	    {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"},
	    {"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
	    {"Effect":"Deny","Action":"iam:DeleteRole","Resource":"*"}
	  ]}`)
	if err != nil {
		t.Fatal(err)
	}

	var g grantSummary
	g.analyzeGrants(doc)
	g.sort()

	if !g.Privileged {
		t.Error("Privileged = false; iam:PassRole makes this role privileged")
	}
	if len(g.Reasons) != 1 {
		t.Errorf("Reasons = %v, want exactly one", g.Reasons)
	}
	want := []string{"iam:PassRole", "s3:GetObject", "s3:PutObject"}
	if len(g.Actions) != len(want) {
		t.Fatalf("Actions = %v, want %v (the Deny statement must not be counted)", g.Actions, want)
	}
	for i := range want {
		if g.Actions[i] != want[i] {
			t.Errorf("Actions[%d] = %q, want %q", i, g.Actions[i], want[i])
		}
	}
}

// Allow + NotAction grants everything except the listed actions, which is
// almost never what the author meant.
func TestAnalyzeGrantsNotAction(t *testing.T) {
	doc, err := parsePolicyDocument(`{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	var g grantSummary
	g.analyzeGrants(doc)
	if !g.Privileged {
		t.Error("Privileged = false for Allow + NotAction")
	}
}

func TestFlagManagedPolicy(t *testing.T) {
	var g grantSummary
	g.flagManagedPolicy("arn:aws:iam::aws:policy/AdministratorAccess")
	if !g.Privileged {
		t.Error("AdministratorAccess did not flag the role as privileged")
	}

	var clean grantSummary
	clean.flagManagedPolicy("arn:aws:iam::aws:policy/ReadOnlyAccess")
	if clean.Privileged {
		t.Error("ReadOnlyAccess flagged the role as privileged")
	}
}

func TestParsePolicyDocumentShapes(t *testing.T) {
	// A single statement object rather than an array.
	doc, err := parsePolicyDocument(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("want 1 statement, got %d", len(doc.Statement))
	}

	// A boolean condition value, which is not a string in the JSON.
	doc, err = parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
	  "Principal":{"AWS":"*"},
	  "Condition":{"Bool":{"aws:MultiFactorAuthPresent":true}}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Statement[0].Condition["Bool"]["aws:MultiFactorAuthPresent"]; len(got) != 1 || got[0] != "true" {
		t.Errorf("boolean condition = %v, want [true]", got)
	}
}

func TestAccountFromPrincipal(t *testing.T) {
	cases := map[string]string{
		"123456789012":                                      "123456789012",
		"arn:aws:iam::123456789012:root":                    "123456789012",
		"arn:aws:iam::123456789012:role/ci":                 "123456789012",
		"arn:aws:sts::123456789012:assumed-role/ci/session": "123456789012",
		"arn:aws:iam::aws:policy/AdministratorAccess":       "",
		"*":          "",
		"not-an-arn": "",
		"12345":      "",
	}
	for in, want := range cases {
		if got := accountFromPrincipal(in); got != want {
			t.Errorf("accountFromPrincipal(%q) = %q, want %q", in, got, want)
		}
	}
}
