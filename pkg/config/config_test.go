package config

import (
	"strings"
	"testing"
)

const valid = `
zitadel:
  domain: https://auth.example.com
github:
  audience: zitadel-ci-broker
identities:
  - subjects: ["repo:my-org/my-repo:ref:refs/heads/*"]
    user: ci-my-org-my-repo-preview
    keyFile: /keys/ci-my-org-my-repo-preview
    scopes: [openid]
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}

	if c.Listen != ":8080" || !strings.Contains(c.GitHub.Issuer, "token.actions") {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestParse_Refusals(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"no audience":    func(s string) string { return strings.Replace(s, "audience: zitadel-ci-broker", "audience: \"\"", 1) },
		"star subject":   func(s string) string { return strings.Replace(s, "repo:my-org/my-repo:ref:refs/heads/*", "*", 1) },
		"no identities":  func(s string) string { return strings.Split(s, "identities:")[0] },
		"missing openid": func(s string) string { return strings.Replace(s, "[openid]", "[profile]", 1) },
		"http domain":    func(s string) string { return strings.Replace(s, "https://auth", "http://auth", 1) },
		"missing keyFile": func(s string) string {
			return strings.Replace(s, "keyFile: /keys/ci-my-org-my-repo-preview", "keyFile: \"\"", 1)
		},
	} {
		if _, err := Parse([]byte(mutate(valid))); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

func TestCompileSubject(t *testing.T) {
	re, err := CompileSubject("repo:o/r:ref:refs/heads/*")
	if err != nil {
		t.Fatal(err)
	}

	if !re.MatchString("repo:o/r:ref:refs/heads/feat/x") {
		t.Error("wildcard must span slashes (IAM StringLike semantics)")
	}

	if re.MatchString("repo:o/rX:ref:refs/heads/y") {
		t.Error("literal segment must not stretch")
	}

	re2, _ := CompileSubject("repo:o/r:pull_request")
	if re2.MatchString("repo:o/r:pull_requestX") {
		t.Error("pattern must be anchored")
	}
}
