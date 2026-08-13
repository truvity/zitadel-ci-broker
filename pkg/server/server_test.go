package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/truvity/zitadel-ci-broker/pkg/config"
	"github.com/truvity/zitadel-ci-broker/pkg/githuboidc"
	"github.com/truvity/zitadel-ci-broker/pkg/mapping"
	"github.com/truvity/zitadel-ci-broker/pkg/mint"
	"github.com/truvity/zitadel-ci-broker/pkg/server"
)

// fakeIssuer stands in for token.actions.githubusercontent.com: OIDC
// discovery + JWKS + token signing.
type fakeIssuer struct {
	srv *httptest.Server
	key jwk.Key
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}

	_ = key.Set(jwk.KeyIDKey, "test-key")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())

	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	set := jwk.NewSet()
	_ = set.AddKey(pub)

	mux := http.NewServeMux()

	f := &fakeIssuer{key: key}
	srv := httptest.NewServer(mux)
	f.srv = srv
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	})

	return f
}

// token mints a workflow-shaped OIDC token.
func (f *fakeIssuer) token(t *testing.T, sub, aud string, expired bool) string {
	t.Helper()

	exp := time.Now().Add(5 * time.Minute)
	if expired {
		exp = time.Now().Add(-5 * time.Minute)
	}

	tok, err := jwt.NewBuilder().
		Issuer(f.srv.URL).
		Subject(sub).
		Audience([]string{aud}).
		IssuedAt(time.Now().Add(-time.Minute)).
		Expiration(exp).
		Claim("repository", "truvity/bar").
		Claim("run_id", "12345").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), f.key))
	if err != nil {
		t.Fatal(err)
	}

	return string(signed)
}

// fakeZitadel stands in for the token endpoint; it asserts the
// jwt-bearer shape and echoes which user's assertion arrived.
func fakeZitadel(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		vals := string(body)

		if !strings.Contains(vals, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer") {
			http.Error(w, "wrong grant", http.StatusBadRequest)
			return
		}

		if !strings.Contains(vals, "scope=openid") {
			http.Error(w, "missing scope", http.StatusBadRequest)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "zitadel-token-ok",
			"token_type":   "Bearer",
			"expires_in":   43199,
		})
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

// writeMachineKey writes a Zitadel KEY_TYPE_JSON document.
func writeMachineKey(t *testing.T, dir string) string {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(raw),
	})

	path := filepath.Join(dir, "ci-truvity-bar-preview")
	doc, _ := json.Marshal(map[string]string{
		"type": "serviceaccount", "keyId": "k1", "userId": "u1", "key": string(pemKey),
	})

	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func newBroker(t *testing.T, issuer *fakeIssuer, zitadel *httptest.Server, keyPath string) http.Handler {
	t.Helper()

	verifier, err := githuboidc.New(context.Background(), issuer.srv.URL, "zitadel-ci-broker")
	if err != nil {
		t.Fatal(err)
	}

	mapper, err := mapping.New([]config.Identity{{
		Subjects: []string{"repo:truvity/bar:ref:refs/heads/*", "repo:truvity/bar:pull_request"},
		User:     "ci-truvity-bar-preview",
		KeyFile:  keyPath,
		Scopes:   []string{"openid", "urn:zitadel:iam:org:project:id:p1:aud"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	return server.New(&server.Deps{
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Verifier: verifier,
		Mapper:   mapper,
		Minter:   &mint.JWTProfileMinter{Domain: zitadel.URL, HTTPClient: zitadel.Client()},
	})
}

func TestExchange(t *testing.T) {
	issuer := newFakeIssuer(t)
	zitadel := fakeZitadel(t)
	keyPath := writeMachineKey(t, t.TempDir())
	broker := newBroker(t, issuer, zitadel, keyPath)

	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/exchange", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		rec := httptest.NewRecorder()
		broker.ServeHTTP(rec, req)

		return rec
	}

	t.Run("happy path", func(t *testing.T) {
		rec := post(issuer.token(t, "repo:truvity/bar:ref:refs/heads/master", "zitadel-ci-broker", false))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
		}

		var tok mint.Token
		if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
			t.Fatal(err)
		}

		if tok.AccessToken != "zitadel-token-ok" {
			t.Errorf("access_token = %q", tok.AccessToken)
		}
	})

	t.Run("pull_request subject maps", func(t *testing.T) {
		rec := post(issuer.token(t, "repo:truvity/bar:pull_request", "zitadel-ci-broker", false))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
		}
	})

	t.Run("foreign repo is refused", func(t *testing.T) {
		rec := post(issuer.token(t, "repo:evil/fork:ref:refs/heads/master", "zitadel-ci-broker", false))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})

	t.Run("wrong audience is refused", func(t *testing.T) {
		rec := post(issuer.token(t, "repo:truvity/bar:ref:refs/heads/master", "sts.amazonaws.com", false))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("expired token is refused", func(t *testing.T) {
		rec := post(issuer.token(t, "repo:truvity/bar:ref:refs/heads/master", "zitadel-ci-broker", true))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("missing token is refused", func(t *testing.T) {
		if rec := post(""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})
}
