package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKubeconfig drops a kubeconfig in a temp dir and points KUBECONFIG
// at it for the duration of the test.
func writeKubeconfig(t *testing.T, body string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	t.Setenv("KUBECONFIG", path)
}

const kubeconfigBoth = `
apiVersion: v1
kind: Config
current-context: sandbox@admin
contexts:
  - name: sandbox@admin
    context: {cluster: sandbox, user: sandbox@admin}
  - name: devel@oidc
    context: {cluster: devel, user: devel-oidc}
users:
  - name: sandbox@admin
    user:
      exec:
        command: aws
        args: [--region, eu-west-1, eks, get-token]
  - name: devel-oidc
    user:
      exec:
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://auth.truvity.xyz
          - --oidc-client-id=383028407031647331
          - --oidc-extra-scope=urn:zitadel:iam:org:project:id:383028401763521256:aud
`

// The arguments must come from the kubeconfig VERBATIM. kubelogin derives
// its cache key from issuer+client+scopes, so inventing or reordering them
// here would miss the session the engineer already has and silently open a
// second browser login.
func TestKubeloginArgsAreTakenVerbatim(t *testing.T) {
	writeKubeconfig(t, kubeconfigBoth)

	got, err := kubeloginArgs("devel@oidc")
	if err != nil {
		t.Fatalf("kubeloginArgs: %v", err)
	}

	want := []string{
		"kubectl", "oidc-login", "get-token",
		"--oidc-issuer-url=https://auth.truvity.xyz",
		"--oidc-client-id=383028407031647331",
		"--oidc-extra-scope=urn:zitadel:iam:org:project:id:383028401763521256:aud",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d args, want %d: %v", len(got), len(want), got)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The estate's kubeconfig also carries `aws eks get-token` contexts. Those
// mint an OPAQUE EKS token: valid for that cluster, meaningless to STS.
// Taking one silently surfaces as "token is not a JWT" three layers from
// the cause, so the refusal has to happen here and name the real problem.
func TestNonOIDCContextIsRefused(t *testing.T) {
	writeKubeconfig(t, kubeconfigBoth)

	_, err := kubeloginArgs("sandbox@admin")
	if err == nil {
		t.Fatal("an aws-eks-get-token context was accepted — it yields an opaque token STS cannot read")
	}

	if !strings.Contains(err.Error(), "not Zitadel") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

// With no --context, the current-context is used. Here that is the
// non-OIDC one, which must still be refused rather than silently used.
func TestCurrentContextIsTheDefault(t *testing.T) {
	writeKubeconfig(t, kubeconfigBoth)

	if _, err := kubeloginArgs(""); err == nil {
		t.Fatal("current-context sandbox@admin should have been refused")
	}
}

func TestUnknownContextIsNamed(t *testing.T) {
	writeKubeconfig(t, kubeconfigBoth)

	_, err := kubeloginArgs("nope@nowhere")
	if err == nil || !strings.Contains(err.Error(), "nope@nowhere") {
		t.Fatalf("unknown context should be named in the error, got: %v", err)
	}
}

// tokenExpiry must reject an opaque token loudly. A broker misconfigured
// to mint opaque tokens would otherwise produce an ExecCredential with no
// expiry, which kubectl caches forever.
func TestTokenExpiryRejectsOpaqueTokens(t *testing.T) {
	if _, err := tokenExpiry("not-a-jwt"); err == nil {
		t.Fatal("an opaque token was accepted")
	}

	// header.payload.signature with {"exp":2000000000}
	jwt := "aGVhZGVy.eyJleHAiOjIwMDAwMDAwMDB9.c2ln"

	got, err := tokenExpiry(jwt)
	if err != nil {
		t.Fatalf("tokenExpiry on a valid JWT: %v", err)
	}

	if !got.Equal(time.Unix(2000000000, 0)) {
		t.Errorf("exp = %v, want %v", got, time.Unix(2000000000, 0))
	}
}

// STS rejects a session name outside its charset with a validation error
// that says nothing about session names, so sanitize rather than pass
// through whatever the OS reports as a username.
func TestSessionNameIsSanitized(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"o-tsarev", "o-tsarev"},
		{"o.tsarev@truvity.com", "o.tsarev@truvity.com"},
		{"DOMAIN\\user", "DOMAIN-user"},
		{"", "zcbctl"},
	} {
		if got := sanitizeSession(tc.in); got != tc.want {
			t.Errorf("sanitizeSession(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if got := sanitizeSession(strings.Repeat("x", 100)); len(got) != 64 {
		t.Errorf("long name not truncated to 64: got %d", len(got))
	}
}
