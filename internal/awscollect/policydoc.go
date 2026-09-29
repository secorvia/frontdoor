package awscollect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// IAM policy JSON is loosely typed: almost every field is "a string, or an
// array of strings". These types absorb that so the rest of the package can
// work with plain slices.

// stringList unmarshals a JSON string, number, bool, or array of those.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*s = nil
		return nil
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		out := make([]string, 0, len(raw))
		for _, r := range raw {
			v, err := scalarString(r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	v, err := scalarString(b)
	if err != nil {
		return err
	}
	*s = []string{v}
	return nil
}

func scalarString(b json.RawMessage) (string, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return "", nil
	}
	if b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return "", err
		}
		return v, nil
	}
	// Booleans and numbers appear in conditions (aws:MultiFactorAuthPresent: true).
	return string(b), nil
}

// principalBlock is the Principal (or NotPrincipal) of a statement.
// "Principal": "*" sets Anyone.
type principalBlock struct {
	Anyone        bool
	AWS           []string
	Federated     []string
	Service       []string
	CanonicalUser []string
}

func (p *principalBlock) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		if v == "*" {
			p.Anyone = true
		} else {
			p.AWS = []string{v}
		}
		return nil
	}
	var obj struct {
		AWS           stringList `json:"AWS"`
		Federated     stringList `json:"Federated"`
		Service       stringList `json:"Service"`
		CanonicalUser stringList `json:"CanonicalUser"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	p.AWS = obj.AWS
	p.Federated = obj.Federated
	p.Service = obj.Service
	p.CanonicalUser = obj.CanonicalUser
	for _, v := range p.AWS {
		if v == "*" {
			p.Anyone = true
		}
	}
	return nil
}

func (p principalBlock) empty() bool {
	return !p.Anyone && len(p.AWS) == 0 && len(p.Federated) == 0 &&
		len(p.Service) == 0 && len(p.CanonicalUser) == 0
}

// conditionBlock preserves operator order-independently but keeps every
// operator and key verbatim; rules need to see exactly what was written.
type conditionBlock map[string]map[string]stringList

// statement is one entry in a policy document.
type statement struct {
	Sid          string          `json:"Sid"`
	Effect       string          `json:"Effect"`
	Principal    principalBlock  `json:"Principal"`
	NotPrincipal *principalBlock `json:"NotPrincipal"`
	Action       stringList      `json:"Action"`
	NotAction    stringList      `json:"NotAction"`
	Resource     stringList      `json:"Resource"`
	NotResource  stringList      `json:"NotResource"`
	Condition    conditionBlock  `json:"Condition"`
}

func (s statement) allows() bool { return strings.EqualFold(s.Effect, "Allow") }

// statementList absorbs "Statement" being a single object or an array.
type statementList []statement

func (l *statementList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var out []statement
		if err := json.Unmarshal(b, &out); err != nil {
			return err
		}
		*l = out
		return nil
	}
	var one statement
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*l = []statement{one}
	return nil
}

type policyDocument struct {
	Version   string        `json:"Version"`
	ID        string        `json:"Id"`
	Statement statementList `json:"Statement"`
}

// parsePolicyDocument decodes an IAM policy document. IAM returns these
// URL-encoded from most APIs, so decode first when the input is not JSON.
func parsePolicyDocument(doc string) (*policyDocument, error) {
	s := strings.TrimSpace(doc)
	if s == "" {
		return nil, fmt.Errorf("empty policy document")
	}
	if !strings.HasPrefix(s, "{") {
		decoded, err := url.QueryUnescape(s)
		if err != nil {
			return nil, fmt.Errorf("policy document is neither JSON nor URL-encoded JSON: %w", err)
		}
		s = strings.TrimSpace(decoded)
	}
	var p policyDocument
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil, fmt.Errorf("parse policy document: %w", err)
	}
	return &p, nil
}
