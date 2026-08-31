package server

import (
	"context"
	"testing"

	"github.com/truvity/zitadel-ci-broker/pkg/mint"
)

// stubMinter records which implementation the handler chose.
type stubMinter struct {
	name   string
	chosen *string
}

func (s stubMinter) Mint(_ context.Context, _ string, _ []string) (*mint.Token, error) {
	*s.chosen = s.name

	return &mint.Token{AccessToken: "t", TokenType: "Bearer", ExpiresIn: 60}, nil
}

// A row's provider selects the minter; a row without one keeps the
// zitadel path, so identities written before providers existed resolve
// exactly as they did. An unknown provider also falls back rather than
// failing closed here -- config.validate has already refused it at load,
// and a mint-time panic would be a worse failure than a wrong-IdP token
// that the target then rejects.
func TestMinterForSelectsByProvider(t *testing.T) {
	var chosen string

	deps := &Deps{
		Minter:  stubMinter{name: "zitadel", chosen: &chosen},
		Minters: map[string]mint.Minter{"cognito": stubMinter{name: "cognito", chosen: &chosen}},
	}

	for _, tc := range []struct {
		provider string
		want     string
	}{
		{"", "zitadel"},
		{"zitadel", "zitadel"},
		{"cognito", "cognito"},
		{"nonsense", "zitadel"},
	} {
		chosen = ""

		if _, err := deps.minterFor(tc.provider).Mint(context.Background(), "k", []string{"s"}); err != nil {
			t.Fatalf("provider %q: %v", tc.provider, err)
		}

		if chosen != tc.want {
			t.Errorf("provider %q chose %q, want %q", tc.provider, chosen, tc.want)
		}
	}
}
