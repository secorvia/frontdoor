package azcollect

import "strings"

// Azure's danger is concentrated in a handful of built-in roles, and in the
// directory roles that sit above the subscription entirely. Owner and User
// Access Administrator are the ones that turn access into ownership: both can
// grant themselves anything else.

// privilegedRoles maps an Azure role name to why it matters on an externally
// reachable identity. Names are lowercase.
var privilegedRoles = map[string]string{
	"owner":                     "can grant itself and anyone else any role in the scope",
	"user access administrator": "can grant itself any role in the scope",
	"role based access control administrator": "can grant itself any role in the scope",
	"contributor":                                 "can create and modify every resource in the scope",
	"global administrator":                        "controls the whole tenant",
	"privileged role administrator":               "can grant itself any directory role",
	"application administrator":                   "can add credentials to any app registration and act as it",
	"cloud application administrator":             "can add credentials to any app registration and act as it",
	"privileged authentication administrator":     "can reset credentials for any account",
	"hybrid identity administrator":               "can alter how the tenant authenticates",
	"domain name administrator":                   "can add a federated domain and mint identities in it",
	"key vault administrator":                     "can read every secret and key in the vault",
	"key vault secrets officer":                   "can read every secret in the vault",
	"key vault certificates officer":              "can issue certificates from the vault",
	"virtual machine contributor":                 "can run code on virtual machines with their managed identities",
	"aks cluster admin":                           "can run workloads under the cluster identity",
	"azure kubernetes service cluster admin role": "can run workloads under the cluster identity",
	"azure kubernetes service rbac cluster admin": "can run workloads in the cluster",
	"managed identity operator":                   "can assign managed identities to resources it creates",
	"automation contributor":                      "can run runbooks under an automation account identity",
	"logic app contributor":                       "can run workflows under a connection identity",
	"data factory contributor":                    "can run pipelines under the factory identity",
	"web plan contributor":                        "can deploy code that runs as an attached identity",
	"website contributor":                         "can deploy code that runs as an attached identity",
}

// wellKnownRoleIDs covers the built-in roles whose GUIDs never change. They
// are only used when the roleDefinitions read is denied - a scan with the
// permission resolves every name properly instead of relying on this.
var wellKnownRoleIDs = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}

// ClassifyRole reports whether an Azure role makes its holder privileged.
func ClassifyRole(role string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(role))
	if why, ok := privilegedRoles[lower]; ok {
		return "holds " + role + ": " + why, true
	}
	// A custom role definition is opaque without reading its actions, but the
	// ones people name "admin" usually are what they sound like.
	if strings.Contains(lower, "admin") || strings.Contains(lower, "owner") {
		return "holds " + role + ", whose name suggests administrative access", true
	}
	return "", false
}

// roleNameFromID pulls the GUID off a role definition id and looks it up in
// the well-known table. An unknown GUID returns empty rather than a guess.
func roleNameFromID(id string) string {
	guid := id
	if i := strings.LastIndex(guid, "/"); i >= 0 && i+1 < len(guid) {
		guid = guid[i+1:]
	}
	return wellKnownRoleIDs[strings.ToLower(guid)]
}

// multiTenantAudience reports whether an app registration's signInAudience
// lets identities from outside this tenant use it at all. This is the Azure
// shape of a door standing open: the app is not just federated, it is
// federated to everyone.
func multiTenantAudience(signInAudience string) (string, bool) {
	switch signInAudience {
	case "AzureADMultipleOrgs":
		return "any Entra ID tenant", true
	case "AzureADandPersonalMicrosoftAccount":
		return "any Entra ID tenant or personal Microsoft account", true
	case "PersonalMicrosoftAccount":
		return "any personal Microsoft account", true
	}
	return "", false
}
