// Package mapping resolves a verified GitHub Actions subject to one
// configured machine identity. The mapping IS the authorization
// policy: no match, no token.
package mapping

import (
	"fmt"
	"regexp"

	"github.com/truvity/zitadel-ci-broker/pkg/config"
)

// Identity is one resolvable machine identity.
type Identity struct {
	User    string
	KeyFile string
	Scopes  []string
}

// Mapper matches subjects against the compiled identity table.
type Mapper struct {
	rows []row
}

type row struct {
	patterns []*regexp.Regexp
	identity Identity
}

// New compiles the config's identity table. Config validation already
// proved every pattern compiles.
func New(ids []config.Identity) (*Mapper, error) {
	m := &Mapper{}

	for i, id := range ids {
		r := row{identity: Identity{User: id.User, KeyFile: id.KeyFile, Scopes: id.Scopes}}

		for _, sub := range id.Subjects {
			re, err := config.CompileSubject(sub)
			if err != nil {
				return nil, fmt.Errorf("identities[%d]: %w", i, err)
			}

			r.patterns = append(r.patterns, re)
		}

		m.rows = append(m.rows, r)
	}

	return m, nil
}

// immutableSub matches GitHub's "immutable references" subject form,
// where the org and repo segments carry `@<databaseID>` suffixes:
//
//	repo:my-org@123/my-repo@456:pull_request
//
// GitHub stamps this form BY DEFAULT on newer organizations (trust-form
// got it from birth; truvity still emits the plain form) — it is not an
// opt-in customization, so the broker must accept both.
var immutableSub = regexp.MustCompile(`^repo:([^:@/]+)@[0-9]+/([^:@/]+)@[0-9]+:`)

// NormalizeSubject strips the `@<databaseID>` suffixes from an
// immutable-form subject's org and repo segments, returning the plain
// form config subjects are written in. A subject in any other shape is
// returned unchanged.
func NormalizeSubject(subject string) string {
	return immutableSub.ReplaceAllString(subject, "repo:$1/$2:")
}

// Resolve returns the first identity whose pattern matches the subject,
// or false. First-match order is documented config semantics; rows
// should not overlap.
//
// The RAW subject is tried first, then its normalized form (immutable
// `@id` suffixes stripped). Raw-first keeps id-pinning available: a
// config row that spells out `repo:org@123/name@456:...` binds to the
// numeric identity and survives repo renames the way GitHub's immutable
// subjects intend; the plain rows the estate writes today match via the
// normalized pass. Name-based matching is the estate's existing policy
// (the config rows are names) — normalization widens the accepted
// TOKEN shape, not the policy.
func (m *Mapper) Resolve(subject string) (Identity, bool) {
	candidates := []string{subject}
	if normalized := NormalizeSubject(subject); normalized != subject {
		candidates = append(candidates, normalized)
	}

	for _, r := range m.rows {
		for _, p := range r.patterns {
			for _, s := range candidates {
				if p.MatchString(s) {
					return r.identity, true
				}
			}
		}
	}

	return Identity{}, false
}
