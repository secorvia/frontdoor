package rules

import (
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// The AWS scanner stops at the role. The GCP scanner never sees where the
// caller came from. Neither is wrong; they are each looking at one side of a
// door and calling it the whole building.
//
// This file joins them. Two mechanisms carry a caller across the boundary, and
// both leave enough behind to be matched:
//
//   - A GCP workload identity pool with an AWS provider. The subject GCP
//     records is the caller's assumed-role ARN, which the GCP collector has
//     already resolved to a canonical role ARN in party.NodeRef.
//   - An AWS role trusting accounts.google.com. The subject there is the GCP
//     service account's numeric unique id - not its email - so the join needs
//     the principal index the GCP collector filled in.
//
// A party that does not resolve to something we scanned stays an entry point:
// an AWS account we were never pointed at is genuinely outside, and pretending
// otherwise would draw an edge into a void.

// DeriveCrossCloudEdges finds the trust edges that leave one cloud for
// another, and reports which doors are internal seams rather than entry
// points.
func DeriveCrossCloudEdges(res *model.Result) (edges []model.Hop, internal map[string]bool) {
	index := model.NewPrincipalIndex(res.Principals)
	internal = map[string]bool{}

	for i := range res.Doors {
		d := &res.Doors[i]
		if !d.IsExternal() || d.NodeID == "" {
			continue
		}

		for j := range d.ExternalParties {
			party := &d.ExternalParties[j]
			from := resolveParty(index, d, *party)
			if from == nil {
				continue
			}
			if from.NodeID == d.NodeID {
				continue // an identity federating into itself is not an edge
			}

			edges = append(edges, model.Hop{
				Kind:         model.EdgeCrossCloud,
				From:         from.NodeID,
				To:           d.NodeID,
				Via:          firstOrEmpty(d.TrustActions),
				Provider:     d.Provider,
				FromProvider: from.Provider,
				Detail: "federates from " + string(from.Provider) + " into " +
					string(d.Provider) + " as " + model.ShortName(d.NodeID),
			})

			// Mark it on the door too. The output has to know this is a seam
			// in the middle of a chain, or it reports the same path twice:
			// once as a chain and once as an entry point of its own.
			party.Internal = true
			internal[doorPartyKey(d, *party)] = true
		}
	}
	return edges, internal
}

// resolveParty returns the principal a door's external party actually is, when
// it is an identity inside a cloud this scan covered.
func resolveParty(index *model.PrincipalIndex, d *model.Door, party model.ExternalParty) *model.Principal {
	// GCP door whose provider is AWS: the collector resolved the role ARN.
	if party.NodeRef != "" {
		if p := index.Node(party.NodeRef); p != nil && p.Provider != d.Provider {
			return p
		}
		return nil
	}

	// AWS door trusting accounts.google.com: the subject is a numeric service
	// account unique id, which only the GCP side can turn into an email.
	if party.Kind == model.PartyGoogle && party.Actor != "" {
		if p := index.Unique(party.Actor); p != nil && p.Provider != d.Provider {
			return p
		}
		return nil
	}

	// A GCP service account bound into another project. Same cloud, but still
	// a hop the chain has to follow.
	if party.Kind == model.PartyGCPServiceAcct {
		if p := index.Node(strings.TrimPrefix(party.Subject, "serviceAccount:")); p != nil {
			return p
		}
	}
	return nil
}

// doorPartyKey identifies one (door, party) pair so the chain builder can skip
// the ones that turned out to be internal seams.
func doorPartyKey(d *model.Door, party model.ExternalParty) string {
	return d.NodeID + "\x00" + party.Display + "\x00" + party.Subject
}
