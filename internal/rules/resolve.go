package rules

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/secorvia/frontdoor/internal/model"
)

// FD022 can only compare a registered thumbprint against reality by opening a
// TLS connection to the issuer. That is the one network call frontdoor makes
// outside your cloud provider, so it is opt-in (--resolve), it is never made
// by default, and it sends nothing: the handshake is aborted as soon as the
// certificate chain arrives.
//
// What the issuer learns from it is that someone connected. What frontdoor
// sends is nothing at all - no account id, no ARN, no request body.

// ResolvedIssuer is the observed certificate chain for one provider.
type ResolvedIssuer struct {
	ProviderARN string   `json:"provider_arn"`
	Issuer      string   `json:"issuer"`
	Thumbprints []string `json:"thumbprints,omitempty"`
	Err         string   `json:"error,omitempty"`
}

// ResolveIssuers fetches the CA thumbprints for every OIDC provider in the
// result. Failures are recorded per issuer and never abort the scan.
func ResolveIssuers(ctx context.Context, res *model.Result, timeout time.Duration) map[string]ResolvedIssuer {
	out := map[string]ResolvedIssuer{}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	for _, p := range res.IdentityProviders {
		if p.Type != model.PrincipalOIDC || p.URL == "" {
			continue
		}
		r := ResolvedIssuer{ProviderARN: p.ARN, Issuer: p.URL}
		prints, err := issuerThumbprints(ctx, p.URL, timeout)
		if err != nil {
			r.Err = err.Error()
		} else {
			r.Thumbprints = prints
		}
		out[p.ARN] = r
	}
	return out
}

// issuerThumbprints returns the SHA-1 fingerprints of the certificates the
// issuer presents, root-most first. AWS registers the thumbprint of the CA
// that signed the leaf, so every cert above the leaf is a candidate.
func issuerThumbprints(ctx context.Context, issuerURL string, timeout time.Duration) ([]string, error) {
	host := model.NormalizeIssuer(issuerURL)
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		ServerName: strings.Split(host, ":")[0],
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Abort as soon as the handshake gives us the chain; no request is sent.
	if err := conn.HandshakeContext(dialCtx); err != nil {
		return nil, err
	}

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errNoChain
	}

	var prints []string
	// Skip the leaf: AWS wants the thumbprint of a CA in the chain.
	for _, cert := range chain[1:] {
		sum := sha1.Sum(cert.Raw)
		prints = append(prints, hex.EncodeToString(sum[:]))
	}
	if len(prints) == 0 {
		// A chain of one means the server sent no intermediate. Report the
		// leaf so the comparison is at least possible.
		sum := sha1.Sum(chain[0].Raw)
		prints = append(prints, hex.EncodeToString(sum[:]))
	}
	return prints, nil
}

type resolveError string

func (e resolveError) Error() string { return string(e) }

const errNoChain = resolveError("issuer presented no certificate chain")
