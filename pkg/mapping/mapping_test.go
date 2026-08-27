package mapping

import (
	"testing"

	"github.com/truvity/zitadel-ci-broker/pkg/config"
)

func newTestMapper(t *testing.T, subjects ...string) *Mapper {
	t.Helper()

	m, err := New([]config.Identity{{
		Subjects: subjects,
		User:     "ci-test",
		KeyFile:  "/keys/ci-test",
		Scopes:   []string{"openid"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return m
}

func TestNormalizeSubject(t *testing.T) {
	cases := []struct{ in, want string }{
		// The immutable form GitHub stamps on newer orgs.
		{
			"repo:trust-form@311546891/phoenix@1318749639:pull_request",
			"repo:trust-form/phoenix:pull_request",
		},
		{
			"repo:trust-form@311546891/phoenix@1318749639:ref:refs/heads/master",
			"repo:trust-form/phoenix:ref:refs/heads/master",
		},
		// The plain form passes through untouched.
		{"repo:truvity/bar:pull_request", "repo:truvity/bar:pull_request"},
		// An @ that is not an id suffix (no digits / wrong position)
		// is left alone rather than half-rewritten.
		{"repo:org@abc/name@1:pull_request", "repo:org@abc/name@1:pull_request"},
		// Non-repo subjects pass through.
		{"not-a-repo-subject", "not-a-repo-subject"},
	}

	for _, c := range cases {
		if got := NormalizeSubject(c.in); got != c.want {
			t.Errorf("NormalizeSubject(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveAcceptsImmutableSubjects(t *testing.T) {
	m := newTestMapper(t,
		"repo:trust-form/phoenix:ref:refs/heads/*",
		"repo:trust-form/phoenix:pull_request",
	)

	for _, sub := range []string{
		"repo:trust-form/phoenix:pull_request",
		"repo:trust-form@311546891/phoenix@1318749639:pull_request",
		"repo:trust-form@311546891/phoenix@1318749639:ref:refs/heads/master",
	} {
		if _, ok := m.Resolve(sub); !ok {
			t.Errorf("Resolve(%q) = unmapped, want match", sub)
		}
	}
}

func TestResolveRejectsForeignSubjects(t *testing.T) {
	m := newTestMapper(t, "repo:trust-form/phoenix:pull_request")

	for _, sub := range []string{
		// A different repo, immutable or plain, stays unmapped.
		"repo:trust-form@311546891/tdm-service@99:pull_request",
		"repo:evil/phoenix:pull_request",
		// Stripping must not let an id-laden LOOKALIKE cross into a
		// plain row for another name.
		"repo:trust-form@311546891/phoenix-fork@7:pull_request",
	} {
		if _, ok := m.Resolve(sub); ok {
			t.Errorf("Resolve(%q) matched, want unmapped", sub)
		}
	}
}

func TestResolveIDPinnedRow(t *testing.T) {
	// A row that spells out the ids binds to the numeric identity: the
	// raw pass matches it, and a DIFFERENT repo id with the same name
	// does not.
	m := newTestMapper(t, "repo:trust-form@311546891/phoenix@1318749639:pull_request")

	if _, ok := m.Resolve("repo:trust-form@311546891/phoenix@1318749639:pull_request"); !ok {
		t.Error("id-pinned row did not match its exact subject")
	}

	if _, ok := m.Resolve("repo:trust-form@311546891/phoenix@2222:pull_request"); ok {
		t.Error("id-pinned row matched a different repo id")
	}

	if _, ok := m.Resolve("repo:trust-form/phoenix:pull_request"); ok {
		t.Error("id-pinned row matched a plain subject (id pin must bind)")
	}
}
