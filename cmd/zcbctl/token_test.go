package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// testJWT is header.payload.signature carrying {"exp":2000000000}. The
// emit path must be exercisable with no network and no kubeconfig, so
// every test here feeds a token rather than obtaining one.
const testJWT = "aGVhZGVy.eyJleHAiOjIwMDAwMDAwMDB9.c2ln"

// ------------------------------------------------------------ tenant ids

func TestGenerateTenantsProducesOneV4IDPerName(t *testing.T) {
	got, err := generateTenants([]string{"primary", "secondary"})
	if err != nil {
		t.Fatalf("generateTenants: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d ids, want 2: %v", len(got), got)
	}

	for name, id := range got {
		if !uuidV4Re.MatchString(id) {
			t.Errorf("%s = %q, not a v4 UUID", name, id)
		}
	}
}

// The whole point of a pair is that the two tenants are different worlds.
// Identical ids would make every isolation test pass by accident.
func TestGenerateTenantsProducesDistinctIDs(t *testing.T) {
	got, err := generateTenants([]string{"primary", "secondary"})
	if err != nil {
		t.Fatalf("generateTenants: %v", err)
	}

	if got["primary"] == got["secondary"] {
		t.Error("both tenants got the same id")
	}
}

// A tenant exists only because a request named it, so a fresh id is a
// fresh empty tenant. Reusing one across runs would let the previous
// run's leftovers decide this run's result.
func TestGenerateTenantsIsFreshEachCall(t *testing.T) {
	first, err := generateTenants([]string{"primary"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := generateTenants([]string{"primary"})
	if err != nil {
		t.Fatal(err)
	}

	if first["primary"] == second["primary"] {
		t.Error("two calls produced the same id — not random")
	}
}

// A repeated name is almost certainly a typo, and collapsing it silently
// would present as a test mysteriously sharing a tenant with itself.
func TestGenerateTenantsRefusesDuplicateNames(t *testing.T) {
	_, err := generateTenants([]string{"primary", "primary"})
	if err == nil {
		t.Fatal("a duplicate tenant name was accepted")
	}

	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("error does not name the duplicate: %v", err)
	}
}

func TestGenerateTenantsRefusesEmptyName(t *testing.T) {
	if _, err := generateTenants([]string{"primary", "  "}); err == nil {
		t.Fatal("an empty tenant name was accepted")
	}
}

func TestGenerateTenantsOfNothingIsNothing(t *testing.T) {
	got, err := generateTenants(parseTenantNames(""))
	if err != nil {
		t.Fatalf("generateTenants: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("got %v, want no tenants", got)
	}
}

func TestParseTenantNames(t *testing.T) {
	cases := map[string][]string{
		"primary,secondary":    {"primary", "secondary"},
		" primary , secondary": {"primary", "secondary"},
		"primary,":             {"primary"},
		"":                     {},
	}

	for raw, want := range cases {
		got := parseTenantNames(raw)
		if len(got) != len(want) {
			t.Errorf("parseTenantNames(%q) = %v, want %v", raw, got, want)

			continue
		}

		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parseTenantNames(%q) = %v, want %v", raw, got, want)

				break
			}
		}
	}
}

// --------------------------------------------------------------- output

// The file holds a live bearer token. 0644 would leave it readable by
// every account on a shared machine for the whole of its lifetime.
func TestOpenOutputCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")

	w, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}

	closeOut()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// O_CREATE applies its mode only when the file did not already exist, so
// without the explicit chmod a stale world-readable file at the same
// path keeps its permissions and quietly receives a live bearer token.
func TestOpenOutputTightensAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.json")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil { //nolint:gosec // deliberately loose: this is the condition under test
		t.Fatal(err)
	}

	_, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	closeOut()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600 — an existing loose file kept its permissions", perm)
	}
}

func TestOpenOutputDashIsStdout(t *testing.T) {
	w, closeOut, err := openOutput("-")
	if err != nil {
		t.Fatal(err)
	}

	defer closeOut()

	if w != os.Stdout {
		t.Error("- should select stdout")
	}
}

// ----------------------------------------------------------- json shape

// emitJSON runs the emit path and decodes the result into a generic map,
// so a test can assert that a key is ABSENT rather than merely empty.
func emitJSON(t *testing.T, tenants map[string]string, apiURL string) map[string]any {
	t.Helper()

	var buf bytes.Buffer

	if err := emitToken(&buf, formatJSON, testJWT, tenants, apiURL); err != nil {
		t.Fatalf("emitToken: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}

	return got
}

func TestJSONCarriesTokenAndExpiry(t *testing.T) {
	got := emitJSON(t, map[string]string{"primary": "id-1"}, "https://api.example.com")

	if got["access_token"] != testJWT {
		t.Errorf("access_token = %v, want the token", got["access_token"])
	}

	// 2000000000 is 2033-05-18T03:33:20Z.
	if got["expires_at"] != "2033-05-18T03:33:20Z" {
		t.Errorf("expires_at = %v, want the token's own exp claim in RFC3339 UTC", got["expires_at"])
	}

	if got["api_url"] != "https://api.example.com" {
		t.Errorf("api_url = %v, want the value passed through unchanged", got["api_url"])
	}

	tenants, ok := got["tenants"].(map[string]any)
	if !ok || tenants["primary"] != "id-1" {
		t.Errorf("tenants = %v, want {primary: id-1}", got["tenants"])
	}
}

// A consumer that asked for no tenants should not have to tell "not
// asked for" apart from "asked for and got nothing".
func TestJSONOmitsTenantsWhenNoneRequested(t *testing.T) {
	got := emitJSON(t, nil, "https://api.example.com")

	if _, present := got["tenants"]; present {
		t.Errorf("tenants key present with no tenants requested: %v", got["tenants"])
	}
}

func TestJSONOmitsAPIURLWhenNotGiven(t *testing.T) {
	got := emitJSON(t, map[string]string{"primary": "id-1"}, "")

	if _, present := got["api_url"]; present {
		t.Errorf("api_url key present when --api-url was not given: %v", got["api_url"])
	}
}

// An opaque token must be refused loudly rather than emitted with no
// expiry: a consumer that cannot see when to re-mint will use it until
// the first mid-suite 401.
func TestJSONRefusesAnOpaqueToken(t *testing.T) {
	var buf bytes.Buffer

	if err := emitToken(&buf, formatJSON, "not-a-jwt", nil, ""); err == nil {
		t.Fatal("an opaque token was accepted")
	}
}

// ------------------------------------------------------------ raw format

// raw is for `TOKEN=$(zcbctl token --format raw)`: the token and a
// newline, nothing else on the stream.
func TestRawFormatPrintsTheTokenAlone(t *testing.T) {
	var buf bytes.Buffer

	if err := emitToken(&buf, formatRaw, testJWT, map[string]string{"primary": "id-1"}, "https://api.example.com"); err != nil {
		t.Fatalf("emitToken: %v", err)
	}

	if got := buf.String(); got != testJWT+"\n" {
		t.Errorf("raw output = %q, want just the token and a newline", got)
	}
}
