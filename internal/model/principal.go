package model

// A Principal is any node the trust graph can pass through: an AWS role, a GCP
// service account, later an Azure app. Doors say how you get in; principals say
// what you are once you are in, and what you can reach from there.
//
// This index exists because a chain's terminal often has no door of its own. A
// service account nobody federates into is invisible in the door list, and it
// is frequently the one holding roles/owner at the end of a chain.
type Principal struct {
	Provider  Provider `json:"provider"`
	NodeID    string   `json:"node_id"` // ARN for AWS, service account email for GCP
	Name      string   `json:"name"`
	AccountID string   `json:"account_id,omitempty"`

	// UniqueID is GCP's numeric service account id. AWS trust policies that
	// federate to Google carry this number and not the email, so it is the
	// only way to join the two clouds' view of the same identity.
	UniqueID string `json:"unique_id,omitempty"`

	// Grants is the flattened permission set: IAM actions on AWS, role names
	// on GCP.
	Grants []string `json:"grants,omitempty"`

	Privileged  bool        `json:"privileged,omitempty"`
	Reasons     []string    `json:"reasons,omitempty"`
	Sensitivity Sensitivity `json:"sensitivity,omitempty"`
	Reach       []string    `json:"reach,omitempty"` // what it can read or change
}

// Sensitivity is how much it matters that something was reached. A chain into
// an account that can only write logs is not the same story as a chain into
// one that can read the customer table, and ranking them the same would bury
// the one worth waking someone up for.
type Sensitivity string

const (
	SensitivityAdmin   Sensitivity = "admin"   // can escalate or take over
	SensitivityData    Sensitivity = "data"    // can read or change stored data
	SensitivityCompute Sensitivity = "compute" // can run code
	SensitivityLow     Sensitivity = "low"     // nothing obviously valuable
)

var sensitivityWeight = map[Sensitivity]int{
	SensitivityAdmin:   5,
	SensitivityData:    4,
	SensitivityCompute: 2,
	SensitivityLow:     1,
}

// Weight ranks a terminal for the chain ordering.
func (s Sensitivity) Weight() int {
	if w, ok := sensitivityWeight[s]; ok {
		return w
	}
	return 1
}

// Describe renders the sensitivity as a phrase that finishes the sentence
// "a chain ending here means an attacker ...".
func (s Sensitivity) Describe() string {
	switch s {
	case SensitivityAdmin:
		return "takes over the account"
	case SensitivityData:
		return "reads your data"
	case SensitivityCompute:
		return "runs code inside your perimeter"
	default:
		return "gains whatever this identity holds"
	}
}

// PrincipalIndex makes the principals addressable by node id and by GCP unique
// id, which is what the cross-cloud join needs.
type PrincipalIndex struct {
	byNode   map[string]*Principal
	byUnique map[string]*Principal
}

// NewPrincipalIndex builds the lookup. It takes a pointer to the slice so the
// index stays valid as the caller keeps its own ordering.
func NewPrincipalIndex(principals []Principal) *PrincipalIndex {
	idx := &PrincipalIndex{
		byNode:   make(map[string]*Principal, len(principals)),
		byUnique: map[string]*Principal{},
	}
	for i := range principals {
		p := &principals[i]
		if p.NodeID != "" {
			idx.byNode[p.NodeID] = p
		}
		if p.UniqueID != "" {
			idx.byUnique[p.UniqueID] = p
		}
	}
	return idx
}

// Node looks up a principal by its canonical id.
func (i *PrincipalIndex) Node(id string) *Principal {
	if i == nil {
		return nil
	}
	return i.byNode[id]
}

// Unique looks up a GCP service account by its numeric unique id.
func (i *PrincipalIndex) Unique(id string) *Principal {
	if i == nil {
		return nil
	}
	return i.byUnique[id]
}
