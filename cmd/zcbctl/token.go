package main

// `zcbctl token` hands the SDK integration suites the one thing they
// cannot mint themselves: a Zitadel access token, plus the fresh tenant
// ids a run needs to be isolated from every other run.
//
// It lives here, next to `aws` and `k8s`, because the hard half of the
// problem is already solved here. The CI/human split — GitHub OIDC proof
// exchanged at the broker on a runner, kubelogin's existing browser
// session borrowed on a laptop — is zitadelToken()'s, and everything
// after the token is identical. A separate tool would have to reproduce
// that branch, and would then be a second thing to keep in step with the
// broker it talks to. Here, `zcbctl token` is the SAME command an
// engineer runs locally and a workflow runs in CI; the only difference is
// which of the two paths inside zitadelToken() fires, which is exactly
// the property the suites need in order to be debuggable off a runner.
//
// It replaces `truectl stand token`, which read a Cognito user and
// password out of SSM. That credential is being retired; this one is
// nobody's password.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	formatJSON = "json"
	formatRaw  = "raw"

	// tokenFileMode: the payload is a live bearer token. The default
	// 0644 would leave it readable by every account on the machine for
	// the whole of the token's lifetime.
	tokenFileMode = 0o600
)

// tokenOutput is the machine contract of `zcbctl token --format json`.
//
// tenants and api_url are omitted entirely rather than emitted empty: a
// consumer that asked for neither should not have to tell "not asked
// for" apart from "asked for and got nothing".
type tokenOutput struct {
	AccessToken string            `json:"access_token"`
	ExpiresAt   string            `json:"expires_at"`
	Tenants     map[string]string `json:"tenants,omitempty"`
	APIURL      string            `json:"api_url,omitempty"`
}

func runToken(argv []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	kubeContext := fs.String("context", "", "kubeconfig context to borrow the Zitadel login from (default: current-context)")
	tenants := fs.String("tenants", "", "comma-separated tenant names to mint fresh ids for (e.g. primary,secondary)")
	apiURL := fs.String("api-url", "", "API base URL to pass through to the consumer")
	format := fs.String("format", formatJSON, "output format: json or raw")

	output := "-"
	fs.StringVar(&output, "output", "-", "write to this file instead of stdout (0600)")
	fs.StringVar(&output, "o", "-", "shorthand for --output")

	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *format != formatJSON && *format != formatRaw {
		return fmt.Errorf("--format must be %s or %s, got %q", formatJSON, formatRaw, *format)
	}

	// Generate the tenants BEFORE reaching for a token: a duplicate name
	// is a typo in the caller's own arguments, and refusing it should not
	// cost a browser login or a broker round trip first.
	ids, err := generateTenants(parseTenantNames(*tenants))
	if err != nil {
		return err
	}

	token, err := zitadelToken(*kubeContext)
	if err != nil {
		return err
	}

	out, closeOut, err := openOutput(output)
	if err != nil {
		return err
	}

	defer closeOut()

	return emitToken(out, *format, token, ids, *apiURL)
}

// emitToken writes the token in the requested shape. Nothing else is
// written to the destination: when it is stdout, this is a machine
// contract and diagnostics belong on stderr (see fail).
func emitToken(w io.Writer, format, token string, tenants map[string]string, apiURL string) error {
	if format == formatRaw {
		// The token alone, so `TOKEN=$(zcbctl token --format raw)` works
		// with no jq on the runner.
		_, err := fmt.Fprintln(w, token)

		return err
	}

	body, err := buildTokenOutput(token, tenants, apiURL)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(body)
}

// buildTokenOutput assembles the JSON body.
//
// expires_at comes from the token's own `exp` claim rather than from a
// lifetime this tool assumes: the broker's ~12h is not a promise, and a
// consumer that has to decide whether to re-mint mid-suite needs the
// real value.
func buildTokenOutput(token string, tenants map[string]string, apiURL string) (*tokenOutput, error) {
	exp, err := tokenExpiry(token)
	if err != nil {
		return nil, err
	}

	return &tokenOutput{
		AccessToken: token,
		ExpiresAt:   exp.UTC().Format(time.RFC3339),
		Tenants:     tenants,
		APIURL:      apiURL,
	}, nil
}

// --------------------------------------------------------------- tenants

// parseTenantNames splits a comma-separated list, dropping empty entries
// so a trailing comma is not an error.
func parseTenantNames(raw string) []string {
	out := []string{}

	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}

	return out
}

// generateTenants returns one fresh identifier per name.
//
// Fresh per invocation, deliberately, rather than fixed ids in a config:
// the platform creates a tenant lazily from the X-Tenant-ID header and
// stores nothing in advance, so a previously unused id IS a new empty
// tenant. Reusing one would let a previous run's leftover documents
// decide this run's result — the classic suite that passes only on a
// second run, or only on a machine that has run it before.
//
// The names belong to the caller, not to this tool: a suite that wants
// `primary` and `secondary` gets those keys, and one that wants `alice`
// and `bob` gets those. Keeping the names out of zcbctl is what lets
// several SDK repositories share one command without any of them being
// privileged.
//
// Duplicates are refused rather than silently collapsed: `primary,primary`
// is almost certainly a typo, and a single-entry map would present as a
// test mysteriously sharing a tenant with itself.
func generateTenants(names []string) (map[string]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(names))

	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, errors.New("empty tenant name in --tenants")
		}

		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("tenant %q listed twice in --tenants", name)
		}

		id, err := uuidV4()
		if err != nil {
			return nil, err
		}

		out[name] = id
	}

	return out, nil
}

// uuidV4 builds a random UUID from crypto/rand.
//
// Hand-rolled rather than pulling a module in for sixteen bytes: this
// repository's dependency list is deliberately short — it is a
// credential-minting service, and every module in it is code that runs
// next to custodied private keys. The layout is fixed by RFC 4122, and
// the one thing that can go wrong, a short read from the entropy source,
// is checked here rather than ignored.
func uuidV4() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read entropy: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	h := hex.EncodeToString(b[:])

	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-"), nil
}

// ---------------------------------------------------------------- output

// openOutput returns the destination and a closer. "-" (the default)
// means stdout, which is not closed.
//
// A file is created 0600 and truncated.
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, tokenFileMode) //nolint:gosec // the path is the caller's own -o destination
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}

	// Re-assert the mode. O_CREATE applies it only when the file did not
	// already exist, so a stale world-readable file at the same path
	// would otherwise keep its permissions and quietly receive a live
	// bearer token.
	if err := f.Chmod(tokenFileMode); err != nil {
		_ = f.Close()

		return nil, nil, fmt.Errorf("chmod %s: %w", path, err)
	}

	return f, func() { _ = f.Close() }, nil
}
