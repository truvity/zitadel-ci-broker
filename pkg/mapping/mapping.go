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

// Resolve returns the first identity whose pattern matches the subject,
// or false. First-match order is documented config semantics; rows
// should not overlap.
func (m *Mapper) Resolve(subject string) (Identity, bool) {
	for _, r := range m.rows {
		for _, p := range r.patterns {
			if p.MatchString(subject) {
				return r.identity, true
			}
		}
	}

	return Identity{}, false
}
