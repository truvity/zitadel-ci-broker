// Package config loads and validates the broker's configuration: which
// GitHub Actions subjects map to which Zitadel machine users, and how
// tokens are minted for them.
//
// The broker is the minimal shim over Zitadel's missing workload
// identity federation (RFC 8693 with federated subjects / RFC 7523 §2.1
// federated credentials): it verifies a GitHub Actions OIDC token,
// maps its subject to a machine user, and mints that user's token via
// the jwt-bearer grant with a custodied key. When Zitadel ships
// federation, this service dissolves by design.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the broker's YAML configuration document.
type Config struct {
	// Listen is the HTTP listen address. Default ":8080".
	Listen string `yaml:"listen"`

	// Zitadel holds the token-issuing side.
	Zitadel Zitadel `yaml:"zitadel"`

	// Cognito holds the client_credentials issuing side. Only required
	// when an identity sets provider: cognito.
	Cognito Cognito `yaml:"cognito"`

	// GitHub holds the token-verifying side.
	GitHub GitHub `yaml:"github"`

	// Identities are the subject→machine-user rows. The mapping IS the
	// authorization policy: a subject matching no row is refused.
	Identities []Identity `yaml:"identities"`
}

// Zitadel configures the issuing instance.
type Zitadel struct {
	// Domain is the instance's issuer URL, e.g.
	// "https://auth.example.com". Assertions carry it as audience; the
	// token endpoint is derived from it.
	Domain string `yaml:"domain"`
}

// The providers a row may name. Empty means ProviderZitadel.
const (
	ProviderZitadel = "zitadel"
	ProviderCognito = "cognito"
)

// Cognito configures the client_credentials issuing side, used by
// identities with provider: cognito.
type Cognito struct {
	// TokenURL is the user pool's HOSTED token endpoint,
	// https://{domain}/oauth2/token -- not the cognito-idp API host.
	// client_credentials additionally requires a resource server with at
	// least one custom scope; a pool without one refuses the grant.
	TokenURL string `yaml:"tokenURL"`
}

// GitHub configures verification of the incoming OIDC token.
type GitHub struct {
	// Issuer of the workflow tokens. Default
	// "https://token.actions.githubusercontent.com".
	Issuer string `yaml:"issuer"`

	// Audience the workflow must request
	// (...?audience=<this>). Required — a token minted for another
	// audience is refused even if the signature is valid.
	Audience string `yaml:"audience"`
}

// Identity maps GitHub Actions subjects to one Zitadel machine user.
type Identity struct {
	// Subjects are the allowed `sub` claim patterns. `*` matches any
	// run of characters (IAM StringLike semantics — deliberately the
	// same grammar the AWS-side CI trust conditions use, so one mental
	// model covers both). Example:
	//   repo:my-org/my-repo:ref:refs/heads/*
	//   repo:my-org/my-repo:pull_request
	Subjects []string `yaml:"subjects"`

	// User is the machine user's username (logging/metrics only; the
	// key file carries the authoritative user ID).
	User string `yaml:"user"`

	// KeyFile is the path to the Zitadel machine key JSON (the
	// Management API's KEY_TYPE_JSON document: type, keyId, key,
	// userId).
	KeyFile string `yaml:"keyFile"`

	// Scopes requested at mint. For zitadel, must include "openid";
	// project-audience scopes (urn:zitadel:iam:org:project:id:{id}:aud)
	// put the target cluster's project into the token's aud. For cognito,
	// the resource server's custom scopes.
	Scopes []string `yaml:"scopes"`

	// Provider selects which IdP mints this row's token. Empty means
	// "zitadel", so every existing row keeps its meaning.
	//
	// The broker's job is unchanged either way -- verify a GitHub
	// workflow's OIDC proof, resolve it to ONE configured identity, mint
	// that identity's token. The IdP is a parameter of that job, not a
	// second job: Cognito has the same gap Zitadel does, in that its
	// token endpoint cannot consume a GitHub OIDC assertion, so a
	// credential has to live somewhere that is not the workflow.
	Provider string `yaml:"provider,omitempty"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	return Parse(data)
}

// Parse validates a config document.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if c.Listen == "" {
		c.Listen = ":8080"
	}

	if c.GitHub.Issuer == "" {
		c.GitHub.Issuer = "https://token.actions.githubusercontent.com"
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *Config) validate() error {
	if !strings.HasPrefix(c.Zitadel.Domain, "https://") {
		return fmt.Errorf("zitadel.domain must be an https:// URL, got %q", c.Zitadel.Domain)
	}

	if !strings.HasPrefix(c.GitHub.Issuer, "https://") {
		return fmt.Errorf("github.issuer must be an https:// URL, got %q", c.GitHub.Issuer)
	}

	if c.GitHub.Audience == "" {
		return fmt.Errorf("github.audience is required (the workflow must request it explicitly)")
	}

	if len(c.Identities) == 0 {
		return fmt.Errorf("identities must not be empty (the mapping is the authorization policy)")
	}

	for i, id := range c.Identities {
		if len(id.Subjects) == 0 {
			return fmt.Errorf("identities[%d]: subjects must not be empty", i)
		}

		for j, sub := range id.Subjects {
			if sub == "" || sub == "*" {
				return fmt.Errorf("identities[%d].subjects[%d]: %q is too broad", i, j, sub)
			}

			if _, err := CompileSubject(sub); err != nil {
				return fmt.Errorf("identities[%d].subjects[%d]: %w", i, j, err)
			}
		}

		if id.User == "" {
			return fmt.Errorf("identities[%d]: user is required", i)
		}

		if id.KeyFile == "" {
			return fmt.Errorf("identities[%d]: keyFile is required", i)
		}

		switch id.Provider {
		case "", ProviderZitadel:
			// openid is what makes Zitadel return a JWT rather than an
			// opaque token; without it zcbctl has nothing to present.
			hasOpenID := false
			for _, s := range id.Scopes {
				if s == "openid" {
					hasOpenID = true
				}
			}

			if !hasOpenID {
				return fmt.Errorf("identities[%d]: scopes must include \"openid\"", i)
			}
		case ProviderCognito:
			// Refuse at load, not at mint: a pool without a resource
			// server rejects client_credentials, and a row with no
			// tokenURL would fail on the first workflow to match it
			// rather than in the PR that added it.
			if c.Cognito.TokenURL == "" {
				return fmt.Errorf(
					"identities[%d]: provider %q requires cognito.tokenURL (the hosted /oauth2/token endpoint)",
					i, id.Provider)
			}

			if !strings.HasPrefix(c.Cognito.TokenURL, "https://") {
				return fmt.Errorf("cognito.tokenURL must be an https:// URL, got %q", c.Cognito.TokenURL)
			}

			if len(id.Scopes) == 0 {
				return fmt.Errorf(
					"identities[%d]: provider %q requires at least one scope (Cognito refuses client_credentials without a resource-server scope)",
					i, id.Provider)
			}
		default:
			return fmt.Errorf("identities[%d]: provider %q is not one of [%q, %q]", i, id.Provider, ProviderZitadel, ProviderCognito)
		}
	}

	return nil
}

// CompileSubject turns an IAM-StringLike-style pattern (`*` = any run
// of characters, everything else literal) into an anchored regexp.
func CompileSubject(pattern string) (*regexp.Regexp, error) {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}

	return regexp.Compile("^" + strings.Join(parts, ".*") + "$")
}
