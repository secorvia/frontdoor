package gcpcollect

import "strings"

// On AWS a role's danger is in its actions. On GCP it is in its role bindings,
// and the dangerous ones are mostly the identity roles: anything that lets the
// holder mint credentials for, or act as, something more privileged than
// itself.

// privilegedRoles maps a GCP role to why it is dangerous on an externally
// reachable service account.
var privilegedRoles = map[string]string{
	"roles/owner":                                "is project owner",
	"roles/editor":                               "can modify every resource in the project",
	"roles/iam.securityAdmin":                    "can grant itself any role in the project",
	"roles/iam.roleAdmin":                        "can rewrite what a role means",
	"roles/iam.organizationRoleAdmin":            "can rewrite roles for the whole organization",
	"roles/resourcemanager.projectIamAdmin":      "can grant itself any role in the project",
	"roles/resourcemanager.folderIamAdmin":       "can grant itself any role in the folder",
	"roles/resourcemanager.organizationAdmin":    "can grant itself any role in the organization",
	"roles/iam.serviceAccountTokenCreator":       "can mint access tokens for other service accounts",
	"roles/iam.serviceAccountUser":               "can attach other service accounts to resources it creates",
	"roles/iam.serviceAccountKeyAdmin":           "can create long-lived keys for other service accounts",
	"roles/iam.serviceAccountAdmin":              "can create and modify service accounts",
	"roles/iam.workloadIdentityPoolAdmin":        "can add new federation providers",
	"roles/iam.workloadIdentityUser":             "can impersonate a service account",
	"roles/cloudfunctions.admin":                 "can deploy code that runs as an attached service account",
	"roles/cloudfunctions.developer":             "can deploy code that runs as an attached service account",
	"roles/run.admin":                            "can deploy a service that runs as an attached service account",
	"roles/run.developer":                        "can deploy a service that runs as an attached service account",
	"roles/compute.admin":                        "can boot an instance with an attached service account",
	"roles/compute.instanceAdmin":                "can boot an instance with an attached service account",
	"roles/compute.instanceAdmin.v1":             "can boot an instance with an attached service account",
	"roles/container.admin":                      "can run workloads under any node service account",
	"roles/cloudbuild.builds.editor":             "can run a build as the Cloud Build service account",
	"roles/composer.worker":                      "can run DAGs under the Composer service account",
	"roles/dataflow.developer":                   "can run a job under a worker service account",
	"roles/deploymentmanager.editor":             "can deploy resources under a passed service account",
	"roles/appengine.appAdmin":                   "can deploy code that runs as the App Engine service account",
	"roles/cloudscheduler.admin":                 "can schedule jobs that run as a service account",
	"roles/orgpolicy.policyAdmin":                "can turn off organization policy constraints",
	"roles/serviceusage.serviceUsageAdmin":       "can enable APIs across the project",
	"roles/storage.admin":                        "can read and rewrite every object in the project",
	"roles/secretmanager.admin":                  "can read every secret in the project",
	"roles/secretmanager.secretAccessor":         "can read secret values",
	"roles/cloudkms.cryptoKeyEncrypterDecrypter": "can decrypt anything the project encrypts",
}

// impersonationRoles let the holder become another service account. These are
// the edges of the chain graph.
var impersonationRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator":       true,
	"roles/iam.workloadIdentityUser":             true,
	"roles/iam.serviceAccountUser":               true,
	"roles/iam.serviceAccountKeyAdmin":           true,
	"roles/iam.serviceAccountOpenIdTokenCreator": true,
}

// ClassifyRole reports whether a role makes its holder privileged, and why.
func ClassifyRole(role string) (string, bool) {
	if why, ok := privilegedRoles[role]; ok {
		return "holds " + role + ": " + why, true
	}
	// Custom roles are opaque without reading their permissions, but the ones
	// people name "admin" or "superuser" usually are.
	lower := strings.ToLower(role)
	if strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/") {
		if strings.Contains(lower, "admin") || strings.Contains(lower, "superuser") || strings.Contains(lower, "owner") {
			return "holds custom role " + role + ", whose name suggests administrative access", true
		}
	}
	return "", false
}

// IsImpersonation reports whether a role creates an impersonation edge.
func IsImpersonation(role string) bool { return impersonationRoles[role] }

// ImpersonationVerb describes an edge for the chain output.
func ImpersonationVerb(role string) string {
	switch role {
	case "roles/iam.serviceAccountTokenCreator":
		return "mint access tokens for"
	case "roles/iam.workloadIdentityUser":
		return "impersonate"
	case "roles/iam.serviceAccountUser":
		return "act as"
	case "roles/iam.serviceAccountKeyAdmin":
		return "create keys for"
	case "roles/iam.serviceAccountOpenIdTokenCreator":
		return "mint ID tokens for"
	}
	return "impersonate"
}
