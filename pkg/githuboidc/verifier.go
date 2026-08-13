// Package githuboidc verifies GitHub Actions OIDC tokens against the
// issuer's JWKS.
//
// The broker verifies in-binary EVEN IF an edge proxy (Envoy
// SecurityPolicy, Authorino, ...) already did — verification is cheap,
// and a service whose safety depends on how it was fronted is a
// misconfiguration away from an open token mint.
package githuboidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims are the verified claims the broker consumes.
type Claims struct {
	Subject    string
	Repository string
	Ref        string
	RunID      string
}

// Verifier validates tokens for one issuer+audience pair.
type Verifier struct {
	issuer   string
	audience string
	cache    *jwk.Cache
	jwksURL  string
}

// New discovers the issuer's JWKS (OIDC discovery) and prepares a
// cached, auto-refreshing key set.
func New(ctx context.Context, issuer, audience string) (*Verifier, error) {
	jwksURL, err := discoverJWKS(ctx, issuer)
	if err != nil {
		return nil, err
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("create JWKS cache: %w", err)
	}

	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(15*time.Minute)); err != nil {
		return nil, fmt.Errorf("register JWKS %s: %w", jwksURL, err)
	}

	return &Verifier{issuer: issuer, audience: audience, cache: cache, jwksURL: jwksURL}, nil
}

// Verify checks signature, issuer, audience and expiry, returning the
// claims the mapping consumes.
func (v *Verifier) Verify(ctx context.Context, raw []byte) (*Claims, error) {
	keys, err := v.cache.Lookup(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("JWKS lookup: %w", err)
	}

	tok, err := jwt.Parse(raw,
		jwt.WithKeySet(keys),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("token rejected: %w", err)
	}

	c := &Claims{}
	if sub, ok := tok.Subject(); ok {
		c.Subject = sub
	}

	if c.Subject == "" {
		return nil, fmt.Errorf("token rejected: empty sub")
	}

	var s string
	if err := tok.Get("repository", &s); err == nil {
		c.Repository = s
	}

	if err := tok.Get("ref", &s); err == nil {
		c.Ref = s
	}

	if err := tok.Get("run_id", &s); err == nil {
		c.RunID = s
	}

	return c, nil
}

// discoverJWKS resolves jwks_uri from the issuer's OIDC discovery
// document.
func discoverJWKS(ctx context.Context, issuer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery for %s: HTTP %d", issuer, resp.StatusCode)
	}

	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
	}

	if doc.JWKSURI == "" {
		return "", fmt.Errorf("OIDC discovery for %s: no jwks_uri", issuer)
	}

	return doc.JWKSURI, nil
}
