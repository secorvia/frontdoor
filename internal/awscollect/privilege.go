package awscollect

import (
	"sort"
	"strings"
)

// What a door grants decides whether it matters. A wide-open trust on a role
// that can only read one S3 prefix is untidy; the same trust on a role that can
// call iam:PassRole is an account takeover.

// privilegedAction maps an action to why it is dangerous on an externally
// reachable role. Keys are lowercase.
var privilegedActions = map[string]string{
	"iam:passrole":                "can pass any role to a service and inherit its permissions",
	"iam:createaccesskey":         "can mint long-lived credentials for any user",
	"iam:createloginprofile":      "can set a console password on any user",
	"iam:updateloginprofile":      "can reset a console password on any user",
	"iam:attachuserpolicy":        "can attach AdministratorAccess to a user",
	"iam:attachrolepolicy":        "can attach AdministratorAccess to a role",
	"iam:attachgrouppolicy":       "can attach AdministratorAccess to a group",
	"iam:putuserpolicy":           "can write an inline admin policy onto a user",
	"iam:putrolepolicy":           "can write an inline admin policy onto a role",
	"iam:putgrouppolicy":          "can write an inline admin policy onto a group",
	"iam:createpolicyversion":     "can rewrite an attached policy to grant anything",
	"iam:setdefaultpolicyversion": "can activate a more permissive existing policy version",
	"iam:updateassumerolepolicy":  "can add itself to the trust policy of any role",
	"iam:createuser":              "can create a new identity outside the federation",
	"iam:addusertogroup":          "can join a privileged group",
	"iam:createrole":              "can create a role with a trust policy of its choosing",
	"iam:createservicelinkedrole": "can create service-linked roles",
	"sts:assumerole":              "can move laterally into other roles",
	"lambda:updatefunctioncode":   "can replace code running under another role",
	"lambda:createfunction":       "can run code under a passed role",
	"glue:updatedevendpoint":      "can run code on an endpoint holding another role",
	"cloudformation:createstack":  "can deploy resources under a passed role",
	"cloudformation:updatestack":  "can redeploy a stack under a passed role",
	"ec2:runinstances":            "can boot an instance with a passed instance profile",
	"ssm:sendcommand":             "can run commands on managed instances",
	"ssm:startsession":            "can open a shell on managed instances",
	"codebuild:createproject":     "can run a build under a passed role",
	"organizations:*":             "can act on the whole organization",
	"sso:*":                       "can grant itself access through IAM Identity Center",
}

// privilegedManagedPolicies are AWS-managed policies that are admin by name.
var privilegedManagedPolicies = map[string]string{
	"arn:aws:iam::aws:policy/AdministratorAccess":                          "AdministratorAccess is attached",
	"arn:aws:iam::aws:policy/IAMFullAccess":                                "IAMFullAccess is attached",
	"arn:aws:iam::aws:policy/PowerUserAccess":                              "PowerUserAccess is attached",
	"arn:aws:iam::aws:policy/job-function/SystemAdministrator":             "SystemAdministrator is attached",
	"arn:aws:iam::aws:policy/AWSOrganizationsFullAccess":                   "AWSOrganizationsFullAccess is attached",
	"arn:aws:iam::aws:policy/aws-service-role/AdministratorAccess-Amplify": "Amplify admin is attached",
}

// grantSummary is the flattened result of reading every policy on a role.
type grantSummary struct {
	Actions    []string
	Reasons    []string
	Privileged bool
}

// analyzeGrants flattens Allow actions from a policy document and records
// every reason the role counts as privileged.
func (g *grantSummary) analyzeGrants(doc *policyDocument) {
	for _, st := range doc.Statement {
		if !st.allows() {
			continue
		}
		// NotAction with Allow is an allow-list inversion: everything except
		// the listed actions. That is almost always broader than intended.
		if len(st.NotAction) > 0 {
			g.add("NotAction:" + strings.Join(st.NotAction, ","))
			g.flag("uses Allow + NotAction, which grants everything not listed")
			continue
		}
		for _, action := range st.Action {
			g.add(action)
			if reason, priv := classifyAction(action); priv {
				g.flag(reason)
			}
		}
	}
}

// classifyAction reports whether a single action string makes the role
// privileged, and why.
func classifyAction(action string) (string, bool) {
	a := strings.ToLower(strings.TrimSpace(action))
	switch a {
	case "*", "*:*":
		return "grants * (full administrative access)", true
	}
	if reason, ok := privilegedActions[a]; ok {
		return "grants " + action + ": " + reason, true
	}
	// Service-level wildcards: iam:*, sts:*, organizations:*
	if service, verb, ok := strings.Cut(a, ":"); ok && verb == "*" {
		switch service {
		case "iam", "sts", "organizations", "sso", "identitystore":
			return "grants " + action + " (full control of identity)", true
		}
		// A prefix wildcard like iam:Put* still covers privileged verbs.
	}
	if strings.HasSuffix(a, "*") {
		prefix := strings.TrimSuffix(a, "*")
		for known, why := range privilegedActions {
			if prefix != "" && strings.HasPrefix(known, prefix) {
				return "grants " + action + ", which covers " + known + ": " + why, true
			}
		}
	}
	return "", false
}

func (g *grantSummary) add(action string) {
	for _, existing := range g.Actions {
		if existing == action {
			return
		}
	}
	g.Actions = append(g.Actions, action)
}

func (g *grantSummary) flag(reason string) {
	g.Privileged = true
	for _, existing := range g.Reasons {
		if existing == reason {
			return
		}
	}
	g.Reasons = append(g.Reasons, reason)
}

// flagManagedPolicy records privilege carried by a managed policy ARN, so a
// role with AdministratorAccess is flagged even if the document read is denied.
func (g *grantSummary) flagManagedPolicy(arn string) {
	if reason, ok := privilegedManagedPolicies[arn]; ok {
		g.flag(reason)
	}
}

func (g *grantSummary) sort() {
	sort.Strings(g.Actions)
	sort.Strings(g.Reasons)
}
