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

	// Scopes requested at mint. Must include "openid"; project-audience
	// scopes (urn:zitadel:iam:org:project:id:{id}:aud) put the target
	// cluster's project into the token's aud.
	Scopes []string `yaml:"scopes"`
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

		hasOpenID := false
		for _, s := range id.Scopes {
			if s == "openid" {
				hasOpenID = true
			}
		}

		if !hasOpenID {
			return fmt.Errorf("identities[%d]: scopes must include \"openid\"", i)
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
