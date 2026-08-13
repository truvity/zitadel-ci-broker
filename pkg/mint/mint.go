// Package mint turns a resolved machine identity into a Zitadel access
// token.
//
// The default Minter implements Path A of the design: sign a JWT-profile
// assertion with the identity's custodied key (Zitadel KEY_TYPE_JSON
// document) and redeem it via the RFC 7523 jwt-bearer grant. The
// interface exists so Path B — RFC 8693 impersonation with a single
// actor credential and `user_id` subject tokens — can replace key
// custody without touching callers.
package mint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token is a minted Zitadel token.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Minter mints tokens for a machine identity.
type Minter interface {
	Mint(ctx context.Context, keyFile string, scopes []string) (*Token, error)
}

// JWTProfileMinter is the Path A implementation.
type JWTProfileMinter struct {
	// Domain is the Zitadel issuer URL (https://...).
	Domain string

	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client

	mu   sync.Mutex
	keys map[string]*machineKey // keyFile → parsed key (keys rotate by file replace + pod restart)
}

// machineKey is Zitadel's KEY_TYPE_JSON machine key document.
type machineKey struct {
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
	UserID string `json:"userId"`

	parsed any // *rsa.PrivateKey
}

// Mint signs the assertion and redeems it at the token endpoint.
func (m *JWTProfileMinter) Mint(ctx context.Context, keyFile string, scopes []string) (*Token, error) {
	key, err := m.load(keyFile)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	assertion := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": key.UserID,
		"sub": key.UserID,
		"aud": m.Domain,
		"iat": now.Unix(),
		"exp": now.Add(55 * time.Minute).Unix(),
	})
	assertion.Header["kid"] = key.KeyID

	signed, err := assertion.SignedString(key.parsed)
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signed},
		"scope":      {strings.Join(scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.Domain+"/oauth/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := m.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}

		_ = json.NewDecoder(resp.Body).Decode(&e)

		return nil, fmt.Errorf("token endpoint: HTTP %d %s %s", resp.StatusCode, e.Error, e.Description)
	}

	var tok Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}

	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint: empty access_token")
	}

	return &tok, nil
}

// load parses and caches a key file.
func (m *JWTProfileMinter) load(keyFile string) (*machineKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keys == nil {
		m.keys = map[string]*machineKey{}
	}

	if k, ok := m.keys[keyFile]; ok {
		return k, nil
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", keyFile, err)
	}

	var k machineKey
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("parse key %s: %w", keyFile, err)
	}

	if k.UserID == "" || k.KeyID == "" || k.Key == "" {
		return nil, fmt.Errorf("key %s: not a Zitadel machine key document", keyFile)
	}

	priv, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(k.Key))
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", keyFile, err)
	}

	k.parsed = priv
	m.keys[keyFile] = &k

	return &k, nil
}
