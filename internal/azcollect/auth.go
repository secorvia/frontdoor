package azcollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Azure's official SDK would give us every credential flow there is. It would
// also pull in the whole azure-sdk-for-go tree, and this project already
// carries the AWS and Google clients; a third vendor SDK for four read-only
// REST calls is not a trade worth making, and the README says so out loud.
//
// So the token flows are here, and only the ones a scanner actually needs:
//
//   - Workload identity (AZURE_FEDERATED_TOKEN_FILE) - how this runs in CI and
//     in AKS, and the same mechanism the tool audits.
//   - Client secret (AZURE_CLIENT_SECRET) - how it runs in older CI.
//   - Managed identity (IMDS) - how it runs on an Azure VM or container.
//   - Azure CLI - how a person runs it at their desk.
//
// There is deliberately no interactive browser or device-code flow. A scanner
// that pops a browser is a scanner that cannot run unattended, and the CLI
// path already covers the human case.

const (
	graphScope = "https://graph.microsoft.com/.default"
	armScope   = "https://management.azure.com/.default"

	imdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
)

// tokenSource hands out access tokens for a scope, caching until expiry.
type tokenSource struct {
	tenantID string
	client   *http.Client

	mu     sync.Mutex
	cached map[string]cachedToken
	method string // how we got them, for the error message and the report
}

type cachedToken struct {
	token   string
	expires time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func newTokenSource(client *http.Client, tenantID string) *tokenSource {
	return &tokenSource{
		tenantID: tenantID,
		client:   client,
		cached:   map[string]cachedToken{},
	}
}

// Token returns a bearer token for the scope, refreshing when it is close to
// expiry. A token is never logged, written to disk, or included in output.
func (t *tokenSource) Token(ctx context.Context, scope string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if c, ok := t.cached[scope]; ok && time.Until(c.expires) > 2*time.Minute {
		return c.token, nil
	}

	token, ttl, method, err := t.acquire(ctx, scope)
	if err != nil {
		return "", err
	}
	t.method = method
	t.cached[scope] = cachedToken{token: token, expires: time.Now().Add(ttl)}
	return token, nil
}

// acquire tries the credential sources in the order a real environment would
// have them, and reports which one worked so the scan can say so.
func (t *tokenSource) acquire(ctx context.Context, scope string) (token string, ttl time.Duration, method string, err error) {
	var attempts []string

	if file := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"); file != "" {
		token, ttl, err = t.federatedToken(ctx, scope, file)
		if err == nil {
			return token, ttl, "workload identity federation", nil
		}
		attempts = append(attempts, "workload identity: "+err.Error())
	}
	if secret := os.Getenv("AZURE_CLIENT_SECRET"); secret != "" {
		token, ttl, err = t.clientSecretToken(ctx, scope, secret)
		if err == nil {
			return token, ttl, "client secret", nil
		}
		attempts = append(attempts, "client secret: "+err.Error())
	}
	if token, ttl, err = t.managedIdentityToken(ctx, scope); err == nil {
		return token, ttl, "managed identity", nil
	} else if !errors.Is(err, errNoIMDS) {
		attempts = append(attempts, "managed identity: "+err.Error())
	}
	if token, ttl, err = t.azureCLIToken(ctx, scope); err == nil {
		return token, ttl, "azure cli", nil
	}
	attempts = append(attempts, "azure cli: "+err.Error())

	return "", 0, "", fmt.Errorf(
		"no usable Azure credentials found. Tried, in order:\n  - %s\n"+
			"Run `az login`, or set AZURE_TENANT_ID with AZURE_CLIENT_ID and either "+
			"AZURE_CLIENT_SECRET or AZURE_FEDERATED_TOKEN_FILE",
		strings.Join(attempts, "\n  - "))
}

// postToken performs the OAuth2 token request every non-IMDS flow shares.
func (t *tokenSource) postToken(ctx context.Context, form url.Values) (string, time.Duration, error) {
	if t.tenantID == "" {
		return "", 0, errors.New("AZURE_TENANT_ID is not set")
	}
	endpoint := "https://login.microsoftonline.com/" + t.tenantID + "/oauth2/v2.0/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	var out tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("token endpoint returned %s and unreadable body", resp.Status)
	}
	if out.AccessToken == "" {
		// The description can carry a correlation id but never a secret.
		return "", 0, fmt.Errorf("token endpoint returned %s: %s", resp.Status, firstLine(out.Description))
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (t *tokenSource) clientSecretToken(ctx context.Context, scope, secret string) (string, time.Duration, error) {
	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		return "", 0, errors.New("AZURE_CLIENT_ID is not set")
	}
	return t.postToken(ctx, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {scope},
	})
}

// federatedToken is the flow this tool exists to audit: a token minted by
// someone else, exchanged for one of yours.
func (t *tokenSource) federatedToken(ctx context.Context, scope, file string) (string, time.Duration, error) {
	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		return "", 0, errors.New("AZURE_CLIENT_ID is not set")
	}
	assertion, err := os.ReadFile(file)
	if err != nil {
		return "", 0, fmt.Errorf("read AZURE_FEDERATED_TOKEN_FILE: %w", err)
	}
	return t.postToken(ctx, url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))},
		"scope":                 {scope},
	})
}

var errNoIMDS = errors.New("no instance metadata service")

// managedIdentityToken asks the Azure instance metadata service. The short
// timeout matters: off an Azure VM the address is simply unreachable, and a
// scanner should not hang for it.
func (t *tokenSource) managedIdentityToken(ctx context.Context, scope string) (string, time.Duration, error) {
	resource := strings.TrimSuffix(scope, "/.default")

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		imdsEndpoint+"?api-version=2018-02-01&resource="+url.QueryEscape(resource), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata", "true")
	if id := os.Getenv("AZURE_CLIENT_ID"); id != "" {
		q := req.URL.Query()
		q.Set("client_id", id)
		req.URL.RawQuery = q.Encode()
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return "", 0, errNoIMDS
	}
	defer resp.Body.Close()

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", 0, errNoIMDS
	}

	ttl := time.Hour
	if secs, err := time.ParseDuration(out.ExpiresIn + "s"); err == nil && secs > 0 {
		ttl = secs
	}
	return out.AccessToken, ttl, nil
}

// azureCLIToken shells out to the Azure CLI, which is what a person at a
// terminal already has logged in.
func (t *tokenSource) azureCLIToken(ctx context.Context, scope string) (string, time.Duration, error) {
	resource := strings.TrimSuffix(scope, "/.default")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{"account", "get-access-token", "--resource", resource, "--output", "json"}
	if t.tenantID != "" {
		args = append(args, "--tenant", t.tenantID)
	}

	cmd := exec.CommandContext(ctx, azCLIName(), args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", 0, fmt.Errorf("az exited %d: %s", exitErr.ExitCode(), firstLine(string(exitErr.Stderr)))
		}
		return "", 0, fmt.Errorf("az not runnable: %w", err)
	}

	var parsed struct {
		AccessToken string `json:"accessToken"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil || parsed.AccessToken == "" {
		return "", 0, errors.New("az returned no access token")
	}
	return parsed.AccessToken, 45 * time.Minute, nil
}

// firstLine keeps an error message to one line. Azure error descriptions can
// run to paragraphs, and only the first sentence is ever the useful part.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
