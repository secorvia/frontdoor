package azcollect

// The shapes frontdoor reads out of Microsoft Graph and ARM. Only the fields
// the tool actually uses are declared - a struct that mirrors the whole API
// would be a lot of surface to keep correct for no benefit, and unknown fields
// are ignored by encoding/json anyway.

// application is an Azure AD app registration. Its federated identity
// credentials are the Azure equivalent of an AWS trust policy.
type application struct {
	ID              string       `json:"id"`    // object id
	AppID           string       `json:"appId"` // client id, joins to the service principal
	DisplayName     string       `json:"displayName"`
	SignInAudience  string       `json:"signInAudience"`
	CreatedDateTime string       `json:"createdDateTime"`
	PasswordCreds   []credential `json:"passwordCredentials"`
	KeyCreds        []credential `json:"keyCredentials"`
}

// credential is a client secret or certificate. Their presence alongside
// federation is the Azure spelling of "we never actually turned the old way
// off".
type credential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	StartDate   string `json:"startDateTime"`
	EndDate     string `json:"endDateTime"`
}

// federatedIdentityCredential is one door into an app registration.
type federatedIdentityCredential struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Audiences   []string `json:"audiences"`
	Description string   `json:"description"`

	// ClaimsMatchingExpression is the newer flexible form, which can match a
	// whole set of subjects with a wildcard. When it is set, Subject is empty.
	ClaimsMatchingExpression *claimsExpression `json:"claimsMatchingExpression"`
}

type claimsExpression struct {
	Value           string `json:"value"`
	LanguageVersion int    `json:"languageVersion"`
}

// servicePrincipal is the identity role assignments are actually made to.
type servicePrincipal struct {
	ID                   string `json:"id"` // object id - the principalId of a role assignment
	AppID                string `json:"appId"`
	DisplayName          string `json:"displayName"`
	ServicePrincipalType string `json:"servicePrincipalType"` // Application | ManagedIdentity | Legacy
	AppOwnerOrgID        string `json:"appOwnerOrganizationId"`
	AccountEnabled       bool   `json:"accountEnabled"`
}

// guestUser is an account from another tenant that holds access in this one.
type guestUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	ExternalUserState string `json:"externalUserState"` // PendingAcceptance | Accepted
}

// graphPage is the envelope Graph wraps every collection in.
type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// --- ARM ---------------------------------------------------------------------

type armPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

type subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
	TenantID       string `json:"tenantId"`
}

type roleAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		Scope            string `json:"scope"`
	} `json:"properties"`
}

type roleDefinition struct {
	ID         string `json:"id"`
	Properties struct {
		RoleName string `json:"roleName"`
		Type     string `json:"type"`
	} `json:"properties"`
}

// userAssignedIdentity is a managed identity that can itself carry federated
// credentials - the shape most AKS and GitHub-to-Azure setups now use.
type userAssignedIdentity struct {
	ID         string `json:"id"` // full ARM resource id
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		PrincipalID string `json:"principalId"`
		ClientID    string `json:"clientId"`
		TenantID    string `json:"tenantId"`
	} `json:"properties"`
}

// armFederatedCredential is the managed-identity form of the same door.
type armFederatedCredential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
	} `json:"properties"`
}
