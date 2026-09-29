package gcpcollect

import "testing"

func TestClassifyRole(t *testing.T) {
	privileged := []string{
		"roles/owner",
		"roles/editor",
		"roles/iam.securityAdmin",
		"roles/iam.serviceAccountTokenCreator",
		"roles/iam.serviceAccountUser",
		"roles/resourcemanager.projectIamAdmin",
		"roles/cloudfunctions.admin",
		"roles/run.admin",
		"roles/compute.instanceAdmin.v1",
		"roles/secretmanager.secretAccessor",
		"roles/iam.workloadIdentityPoolAdmin",
	}
	for _, r := range privileged {
		if _, ok := ClassifyRole(r); !ok {
			t.Errorf("ClassifyRole(%q) = not privileged, want privileged", r)
		}
	}

	benign := []string{
		"roles/viewer",
		"roles/logging.viewer",
		"roles/monitoring.viewer",
		"roles/storage.objectViewer",
		"roles/bigquery.dataViewer",
		"roles/iam.securityReviewer",
	}
	for _, r := range benign {
		if why, ok := ClassifyRole(r); ok {
			t.Errorf("ClassifyRole(%q) = privileged (%s), want not privileged", r, why)
		}
	}
}

// A custom role is opaque without reading its permissions. We do not pretend
// to know what it does - but a role someone named "admin" is worth saying
// something about, as a guess clearly labelled as one.
func TestClassifyCustomRole(t *testing.T) {
	why, ok := ClassifyRole("projects/acme-prod/roles/deployAdmin")
	if !ok {
		t.Fatal("a custom role named ...Admin was not flagged at all")
	}
	if !contains(why, "name suggests") {
		t.Errorf("the reason does not mark this as a guess from the name: %q", why)
	}

	if _, ok := ClassifyRole("projects/acme-prod/roles/logReader"); ok {
		t.Error("a custom role with an innocuous name was flagged")
	}
}

func TestIsImpersonation(t *testing.T) {
	yes := []string{
		"roles/iam.serviceAccountTokenCreator",
		"roles/iam.workloadIdentityUser",
		"roles/iam.serviceAccountUser",
		"roles/iam.serviceAccountKeyAdmin",
	}
	for _, r := range yes {
		if !IsImpersonation(r) {
			t.Errorf("IsImpersonation(%q) = false, want true", r)
		}
		if ImpersonationVerb(r) == "" {
			t.Errorf("ImpersonationVerb(%q) is empty", r)
		}
	}

	no := []string{"roles/owner", "roles/viewer", "roles/storage.admin"}
	for _, r := range no {
		if IsImpersonation(r) {
			t.Errorf("IsImpersonation(%q) = true, want false", r)
		}
	}
}

// roles/owner makes the holder privileged but is not itself an impersonation
// edge. Confusing the two would either invent chain hops or miss real ones.
func TestPrivilegedIsNotTheSameAsImpersonation(t *testing.T) {
	if _, ok := ClassifyRole("roles/owner"); !ok {
		t.Error("roles/owner should be privileged")
	}
	if IsImpersonation("roles/owner") {
		t.Error("roles/owner is not an impersonation edge")
	}
}

func TestSamlEntityID(t *testing.T) {
	const metadata = `<?xml version="1.0"?><EntityDescriptor entityID="https://idp.acme.com/saml" xmlns="urn:oasis"/>`
	if got := samlEntityID(metadata); got != "https://idp.acme.com/saml" {
		t.Errorf("samlEntityID = %q", got)
	}
	if got := samlEntityID("no entity here"); got != "" {
		t.Errorf("samlEntityID on junk = %q, want empty", got)
	}
}

func TestKeyID(t *testing.T) {
	name := "projects/acme/serviceAccounts/ci@acme.iam.gserviceaccount.com/keys/abc123"
	if got := keyID(name); got != "abc123" {
		t.Errorf("keyID = %q, want abc123", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
