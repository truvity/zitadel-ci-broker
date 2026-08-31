package mint

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCreds(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cognito.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// The credentials must travel as HTTP Basic, not as form fields — a
// confidential client's secret in a request body ends up in logs.
func TestCognitoMintUsesBasicAuthAndClientCredentials(t *testing.T) {
	var gotAuth, gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")

		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	m := &CognitoMinter{TokenURL: srv.URL, HTTPClient: srv.Client()}

	tok, err := m.Mint(context.Background(),
		writeCreds(t, `{"client_id":"cid","client_secret":"sec"}`),
		[]string{"dms/read"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if tok.AccessToken != "tok" {
		t.Errorf("access_token = %q, want tok", tok.AccessToken)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:sec"))
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}

	if strings.Contains(gotBody, "sec") {
		t.Errorf("the secret reached the request body: %q", gotBody)
	}

	if !strings.Contains(gotBody, "grant_type=client_credentials") {
		t.Errorf("body = %q, want grant_type=client_credentials", gotBody)
	}

	if !strings.Contains(gotBody, "scope=dms%2Fread") {
		t.Errorf("body = %q, want the scope", gotBody)
	}
}

// Cognito refuses client_credentials without a resource-server scope, so
// an empty list is a configuration error and not "every scope".
func TestCognitoMintRefusesEmptyScopes(t *testing.T) {
	m := &CognitoMinter{TokenURL: "https://example.invalid/oauth2/token"}

	_, err := m.Mint(context.Background(), writeCreds(t, `{"client_id":"c","client_secret":"s"}`), nil)
	if err == nil {
		t.Fatal("want an error for empty scopes, got nil")
	}
}

func TestCognitoMintRejectsIncompleteCredentials(t *testing.T) {
	m := &CognitoMinter{TokenURL: "https://example.invalid/oauth2/token"}

	_, err := m.Mint(context.Background(), writeCreds(t, `{"client_id":"c"}`), []string{"s"})
	if err == nil {
		t.Fatal("want an error when client_secret is missing, got nil")
	}
}

// The upstream error text must survive: invalid_client is what a pool
// answers when the app client has no resource-server scope, which reads
// as a credential fault and is not one.
func TestCognitoMintSurfacesUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"no scopes"}`))
	}))
	defer srv.Close()

	m := &CognitoMinter{TokenURL: srv.URL, HTTPClient: srv.Client()}

	_, err := m.Mint(context.Background(),
		writeCreds(t, `{"client_id":"c","client_secret":"s"}`), []string{"s"})
	if err == nil {
		t.Fatal("want an error on HTTP 400, got nil")
	}

	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error %q does not name invalid_client", err)
	}
}
