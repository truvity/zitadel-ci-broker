package mapping_test

import (
	"testing"

	"github.com/truvity/zitadel-ci-broker/pkg/config"
	"github.com/truvity/zitadel-ci-broker/pkg/mapping"
)

// The case the selector exists for: one workflow, two identities. The
// zitadel row is listed first, so without narrowing the cognito row is
// unreachable by list order alone.
func TestResolveForPicksTheRequestedProvider(t *testing.T) {
	sub := "repo:truvity/sdk-typescript-internal:ref:refs/heads/main"

	m, err := mapping.New([]config.Identity{
		{Subjects: []string{"repo:truvity/sdk-typescript-internal:ref:refs/heads/*"}, User: "z", KeyFile: "z.json", Scopes: []string{"openid"}},
		{Subjects: []string{"repo:truvity/sdk-typescript-internal:ref:refs/heads/*"}, User: "c", KeyFile: "c.json", Scopes: []string{"dms/e2e"}, Provider: "cognito"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ want, user string }{
		{"", "z"},        // unchanged: first match wins
		{"zitadel", "z"}, // the empty row answers to its default name
		{"cognito", "c"}, // otherwise unreachable
	} {
		got, ok := m.ResolveFor(sub, tc.want)
		if !ok {
			t.Fatalf("provider %q: no match", tc.want)
		}

		if got.User != tc.user {
			t.Errorf("provider %q resolved to %q, want %q", tc.want, got.User, tc.user)
		}
	}
}

// Narrowing removes candidates; it never admits a subject no row matches.
func TestResolveForStillRefusesUnmappedSubjects(t *testing.T) {
	m, err := mapping.New([]config.Identity{
		{Subjects: []string{"repo:truvity/other:ref:refs/heads/*"}, User: "z", KeyFile: "z.json", Scopes: []string{"openid"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.ResolveFor("repo:truvity/sdk-go-internal:pull_request", "zitadel"); ok {
		t.Error("an unmapped subject resolved")
	}

	// A provider with no rows at all must refuse, not fall through.
	if _, ok := m.ResolveFor("repo:truvity/other:ref:refs/heads/main", "cognito"); ok {
		t.Error("resolved a provider that has no rows")
	}
}
