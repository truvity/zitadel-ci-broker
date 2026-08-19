// Command zcbctl turns a Zitadel identity into AWS credentials and
// Kubernetes tokens, for humans and for CI, through interfaces both
// already speak.
//
//	zcbctl aws --role <name|arn>   → AWS credential_process JSON
//	zcbctl k8s                     → client.authentication.k8s.io ExecCredential
//
// The two callers differ ONLY in how the Zitadel token is obtained:
//
//	CI     GitHub Actions OIDC token → this broker's /exchange → machine token
//	human  kubectl oidc-login, reusing the browser session and cache it
//	       already maintains for kubectl
//
// Everything after that is identical, which is the point: one identity
// plane, two surfaces, no second login and no credential to store.
//
// The human path deliberately SHELLS OUT to kubelogin rather than
// implementing OIDC. kubelogin already owns the browser flow, the local
// callback port, the token cache and silent refresh; reimplementing that
// here would mean a second cache that can disagree with the first, and a
// second login prompt when it does. The arguments are read from the
// kubeconfig itself (see kubeloginArgs) so they cannot drift from the
// context kubectl uses — kubelogin derives its cache key from
// issuer+client+scopes, and a single mismatched scope silently opens a
// SECOND browser login instead of reusing the session.
package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// userAgent is explicit because the Cloudflare edge in front of the
	// broker 403s default library agents — the request never reaches the
	// service, and the failure looks like a broker outage rather than a
	// filtered client.
	userAgent = "zcbctl/1.0"

	// githubAudience is the audience the broker requires GitHub to have
	// signed the proof for.
	githubAudience = "zitadel-ci-broker"

	defaultBroker = "https://zitadel-ci-broker.kernel.truvity.xyz/exchange"
	defaultRegion = "eu-central-1"

	// earlyRefresh keeps the last minute of a token's life unused: one
	// expiring mid-request is a confusing 401 rather than a clean retry.
	earlyRefresh = time.Minute

	httpTimeout = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: zcbctl <aws|k8s> [flags]"))
	}

	var err error

	switch os.Args[1] {
	case "aws":
		err = runAWS(os.Args[2:])
	case "k8s":
		err = runK8s(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q (want aws or k8s)", os.Args[1])
	}

	if err != nil {
		fail(err)
	}
}

// fail writes to stderr and exits non-zero. stdout is a machine contract
// in both subcommands and must never carry diagnostics.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "zcbctl:", err)
	os.Exit(1)
}

// ---------------------------------------------------------------- token

// zitadelToken returns a Zitadel token for whoever is running, without
// ever writing it to disk.
func zitadelToken(context string) (string, error) {
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
		return ciToken()
	}

	return humanToken(context)
}

// ciToken exchanges the workflow's GitHub OIDC proof for a Zitadel
// machine-user token. The mapping from `sub` to machine user lives in the
// broker and IS the authorization policy: an unmapped subject gets 403,
// and the refusal never echoes the map.
func ciToken() (string, error) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if reqTok == "" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_TOKEN missing (workflow needs permissions: id-token: write)")
	}

	var gh struct {
		Value string `json:"value"`
	}

	if err := getJSON(reqURL+"&audience="+url.QueryEscape(githubAudience),
		map[string]string{"Authorization": "bearer " + reqTok}, &gh); err != nil {
		return "", fmt.Errorf("github oidc token: %w", err)
	}

	broker := os.Getenv("ZCB_BROKER")
	if broker == "" {
		broker = defaultBroker
	}

	var ex struct {
		AccessToken string `json:"access_token"`
	}

	if err := postJSON(broker, map[string]string{"Authorization": "Bearer " + gh.Value}, &ex); err != nil {
		return "", fmt.Errorf("broker exchange: %w", err)
	}

	if ex.AccessToken == "" {
		return "", errors.New("broker returned no access_token")
	}

	return ex.AccessToken, nil
}

// humanToken runs kubelogin with the kubeconfig's own arguments and takes
// the token out of its ExecCredential.
func humanToken(context string) (string, error) {
	args, err := kubeloginArgs(context)
	if err != nil {
		return "", err
	}

	out, err := exec.Command(args[0], args[1:]...).Output() //nolint:gosec // args come from the user's own kubeconfig
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("kubelogin: %s", strings.TrimSpace(string(ee.Stderr)))
		}

		return "", fmt.Errorf("kubelogin: %w", err)
	}

	var cred execCredential
	if err := json.Unmarshal(out, &cred); err != nil {
		return "", fmt.Errorf("parse kubelogin output: %w", err)
	}

	if cred.Status.Token == "" {
		return "", errors.New("kubelogin returned no token")
	}

	return cred.Status.Token, nil
}

// kubeloginArgs lifts the exec command out of the kubeconfig's CURRENT
// context, so this tool authenticates as exactly the same client, with
// exactly the same scopes, as kubectl does — and therefore hits the same
// kubelogin cache instead of prompting a second browser login.
func kubeloginArgs(context string) ([]string, error) {
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locate kubeconfig: %w", err)
		}

		path = filepath.Join(home, ".kube", "config")
	}

	// KUBECONFIG may list several files; the first wins for our purposes.
	if i := strings.IndexByte(path, os.PathListSeparator); i >= 0 {
		path = path[:i]
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is the caller's own kubeconfig
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}

	var kc kubeConfig
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}

	want := context
	if want == "" {
		want = kc.CurrentContext
	}

	userName := ""

	for _, c := range kc.Contexts {
		if c.Name == want {
			userName = c.Context.User

			break
		}
	}

	if userName == "" {
		return nil, fmt.Errorf("kubeconfig %s has no context named %q", path, want)
	}

	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}

		if u.User.Exec == nil || u.User.Exec.Command == "" {
			return nil, fmt.Errorf("kubeconfig user %q has no exec credential plugin", userName)
		}

		argv := append([]string{u.User.Exec.Command}, u.User.Exec.Args...)

		// Refuse anything that is not kubelogin. The estate's kubeconfig
		// also carries `aws eks get-token` contexts, which mint an OPAQUE
		// EKS token: it authenticates to that cluster and is meaningless
		// to STS. Taking it silently produces "token is not a JWT" three
		// layers away from the cause, so name the cause here.
		if !strings.Contains(strings.Join(argv, " "), "oidc-login") {
			return nil, fmt.Errorf(
				"context %q authenticates with %q, not Zitadel — pass --context for an OIDC context (e.g. devel@oidc)",
				want, strings.Join(argv[:min(3, len(argv))], " "))
		}

		return argv, nil
	}

	return nil, fmt.Errorf("kubeconfig has no user named %q", userName)
}

// ------------------------------------------------------------------ aws

func runAWS(argv []string) error {
	fs := flag.NewFlagSet("aws", flag.ExitOnError)
	kubeContext := fs.String("context", "", "kubeconfig context to borrow the Zitadel login from (default: current-context)")
	role := fs.String("role", "", "role name or full ARN to assume (required)")
	account := fs.String("account", "", "account id, when --role is a bare name")
	region := fs.String("region", defaultRegion, "STS region")
	session := fs.String("session-name", "", "role session name (default: current user)")

	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *role == "" {
		return errors.New("--role is required")
	}

	arn := *role
	if !strings.HasPrefix(arn, "arn:") {
		if *account == "" {
			return errors.New("--account is required when --role is not a full ARN")
		}

		arn = fmt.Sprintf("arn:aws:iam::%s:role/%s", *account, *role)
	}

	name := *session
	if name == "" {
		name = sessionName()
	}

	token, err := zitadelToken(*kubeContext)
	if err != nil {
		return err
	}

	creds, err := assumeRoleWithWebIdentity(arn, name, *region, token)
	if err != nil {
		return err
	}

	// The credential_process contract: this JSON on stdout, nothing else.
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"Version":         1,
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"SessionToken":    creds.SessionToken,
		"Expiration":      creds.Expiration.UTC().Format(time.RFC3339),
	})
}

type stsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// assumeRoleWithWebIdentity calls STS directly. The call is UNSIGNED —
// the web identity token is the only credential — so this needs no AWS
// SDK and no ambient AWS configuration, which matters: the whole point is
// to work for someone who has no AWS account at all.
func assumeRoleWithWebIdentity(roleARN, sessionName, region, token string) (*stsCredentials, error) {
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {roleARN},
		"RoleSessionName":  {sessionName},
		"WebIdentityToken": {token},
	}

	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com/", region)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("sts: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("sts: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}

		if xml.Unmarshal(body, &e) == nil && e.Error.Code != "" {
			// InvalidIdentityToken means AWS could not validate the token
			// at all; AccessDenied means it did, and the role's trust said
			// no. The distinction is the whole diagnosis, so keep both.
			return nil, fmt.Errorf("sts %s: %s", e.Error.Code, e.Error.Message)
		}

		return nil, fmt.Errorf("sts http %d", resp.StatusCode)
	}

	var out struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string    `xml:"AccessKeyId"`
				SecretAccessKey string    `xml:"SecretAccessKey"`
				SessionToken    string    `xml:"SessionToken"`
				Expiration      time.Time `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}

	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("sts: parse response: %w", err)
	}

	c := out.Result.Credentials
	if c.AccessKeyID == "" {
		return nil, errors.New("sts returned no credentials")
	}

	return &stsCredentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expiration:      c.Expiration,
	}, nil
}

// ------------------------------------------------------------------ k8s

func runK8s(argv []string) error {
	fs := flag.NewFlagSet("k8s", flag.ExitOnError)
	kubeContext := fs.String("context", "", "kubeconfig context to borrow the Zitadel login from (default: current-context)")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	token, err := zitadelToken(*kubeContext)
	if err != nil {
		return err
	}

	exp, err := tokenExpiry(token)
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(execCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: execCredentialStatus{
			Token:               token,
			ExpirationTimestamp: exp.Add(-earlyRefresh).UTC().Format(time.RFC3339),
		},
	})
}

// tokenExpiry reads `exp` out of the JWT payload. No signature check: the
// API server and STS both verify the token themselves, and this value is
// only used to tell kubectl when to ask again.
func tokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("token is not a JWT (broker returned an opaque token?)")
	}

	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode token payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parse token payload: %w", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, errors.New("token has no exp claim")
	}

	return time.Unix(claims.Exp, 0), nil
}

// ---------------------------------------------------------------- shared

type (
	execCredential struct {
		APIVersion string               `json:"apiVersion"`
		Kind       string               `json:"kind"`
		Status     execCredentialStatus `json:"status"`
	}

	execCredentialStatus struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp,omitempty"`
	}

	kubeConfig struct {
		CurrentContext string `yaml:"current-context"`
		Contexts       []struct {
			Name    string `yaml:"name"`
			Context struct {
				User string `yaml:"user"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Exec *struct {
					Command string   `yaml:"command"`
					Args    []string `yaml:"args"`
				} `yaml:"exec"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
)

func sessionName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return sanitizeSession(u.Username)
	}

	return "zcbctl"
}

// sanitizeSession keeps the name inside the charset STS accepts; an
// invalid one fails the assume with a validation error that says nothing
// about session names.
func sanitizeSession(in string) string {
	var b strings.Builder

	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}

	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}

	if out == "" {
		out = "zcbctl"
	}

	return out
}

// base64URL is the unpadded URL-safe alphabet JWTs use.
var base64URL = base64.URLEncoding

func base64URLDecode(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}

	return base64URL.DecodeString(s)
}

func getJSON(rawURL string, headers map[string]string, out any) error {
	return doJSON(http.MethodGet, rawURL, headers, out)
}

func postJSON(rawURL string, headers map[string]string, out any) error {
	return doJSON(http.MethodPost, rawURL, headers, out)
}

func doJSON(method, rawURL string, headers map[string]string, out any) error {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", userAgent)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		// 403 from the broker means the workflow's `sub` is not in the
		// mapping — the map IS the policy, and it never echoes itself.
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return json.Unmarshal(body, out)
}
