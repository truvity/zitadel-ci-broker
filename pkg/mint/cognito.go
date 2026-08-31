package mint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// CognitoMinter mints an AWS Cognito access token with the
// client_credentials grant.
//
// Why the broker has to do this at all: Cognito's token endpoint cannot
// consume a GitHub Actions OIDC assertion any more than Zitadel's can.
// User pools federate USERS (hosted UI, authorization_code); the
// machine-to-machine grant takes a client id and secret and nothing else.
// So a credential must live somewhere that is not the workflow, and the
// broker is where the estate already put that problem.
//
// Credentials are custodied exactly as the Zitadel machine keys are — a
// JSON file per identity, referenced by the mapping row — so key handling,
// mounting and rotation stay one mechanism rather than two.
type CognitoMinter struct {
	// TokenURL is the pool's HOSTED endpoint, https://{domain}/oauth2/token.
	// The cognito-idp API host does NOT serve this grant.
	TokenURL string

	// HTTPClient is optional; http.DefaultClient when nil.
	HTTPClient *http.Client

	mu    sync.Mutex
	cache map[string]*cognitoClient
}

// cognitoClient is one identity's app-client credentials.
type cognitoClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Mint exchanges the identity's client credentials for an access token.
// The signature matches Minter so the server selects an implementation
// without knowing which IdP it is talking to.
func (m *CognitoMinter) Mint(ctx context.Context, keyFile string, scopes []string) (*Token, error) {
	client, err := m.load(keyFile)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	// Cognito refuses client_credentials without a resource-server scope,
	// so an empty list is a configuration error rather than "all scopes".
	// config.validate already rejects it; this keeps the minter honest on
	// its own.
	if len(scopes) == 0 {
		return nil, fmt.Errorf("cognito: at least one scope is required for client_credentials")
	}

	form.Set("scope", strings.Join(scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic auth, not form fields: a confidential client's secret belongs
	// in the Authorization header, where it does not land in a request-body
	// log line.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(client.ClientID+":"+client.ClientSecret)))

	httpClient := m.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cognito token endpoint: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}

		_ = json.NewDecoder(resp.Body).Decode(&e)

		// invalid_client is the one worth naming: it is what a pool
		// answers when the app client exists but has no resource-server
		// scope, which reads as a credential problem and is not one.
		return nil, fmt.Errorf("cognito token endpoint: HTTP %d %s %s", resp.StatusCode, e.Error, e.Description)
	}

	var tok Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("cognito token endpoint: %w", err)
	}

	if tok.AccessToken == "" {
		return nil, fmt.Errorf("cognito token endpoint: empty access_token")
	}

	return &tok, nil
}

// load parses and caches a credentials file, mirroring JWTProfileMinter's
// custody model.
func (m *CognitoMinter) load(keyFile string) (*cognitoClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.cache[keyFile]; ok {
		return c, nil
	}

	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read cognito credentials: %w", err)
	}

	var c cognitoClient
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse cognito credentials: %w", err)
	}

	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("cognito credentials %q: client_id and client_secret are both required", keyFile)
	}

	if m.cache == nil {
		m.cache = map[string]*cognitoClient{}
	}

	m.cache[keyFile] = &c

	return &c, nil
}
