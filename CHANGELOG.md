# Changelog

## [Unreleased]

### Removed
- **Cognito support, added in 0.7.0, is withdrawn.** The `provider`
  field on an identity row, the `?provider=` selector on `/exchange` and
  the Cognito minter are all gone; the broker is Zitadel-only again, as
  its own README scopes it ("fills exactly that gap and nothing more").

  Why so soon: the consumer that motivated it does not need a broker.
  Reading the Cognito credential from SSM under an assumed role is a
  plain AWS operation, so the tool that mints platform tokens for the
  integration suites needs an AWS session and nothing from this service.
  Keeping the provider here would have coupled test tooling to the
  release cycle of a credential-minting service — every fix to the
  former redeploying the latter — for no shared code.

  Nothing consumed it: no identity row named `cognito`, and the pool it
  anticipated was never provisioned. The token tool lives in its own
  repository instead.

## [0.7.0]

### Added
- **Cognito as a second token provider.** An identity row may name
  `provider: cognito`, and the broker mints its token with the
  `client_credentials` grant instead of Zitadel's `jwt-bearer`. Cognito
  has the same gap this broker exists for — its token endpoint cannot
  consume a GitHub Actions OIDC assertion, because user pools federate
  *users* and the machine-to-machine grant takes a client id and secret —
  so the credential lives here rather than in a workflow. Empty
  `provider` still means zitadel, so existing rows are unchanged.

  Credentials are custodied as a JSON file per identity, exactly as the
  Zitadel machine keys are, and travel as HTTP Basic rather than form
  fields so a confidential client's secret never reaches a request body.

- **`POST /exchange?provider=`** narrows resolution to rows of one
  provider. One workflow legitimately needs two identities — zitadel for
  its kubeconfig and AWS credentials, cognito for the platform token its
  tests present — and both rows carry the same `sub` pattern because it
  is the same workflow. Without the selector the second was unreachable
  by config list order alone. Absent, resolution is unchanged; narrowing
  only ever removes candidates, never admits a subject no row matches.

### Note
- The repository keeps its name. Renaming would touch every consumer's
  committed `bin/zcbctl` wrapper (the release repo is baked into it),
  ADR-030's references and the deployment; the functional change lands
  first on a stable name.
- 0.4.1 through 0.6.3 have no entries here. Those were cut by the
  auto-release lane for Renovate bumps, which writes none.

## [0.4.0]

### Documentation
- `setup-zcbctl`: document that the action must be pinned by commit SHA
  **and** given `version:` explicitly. The two answer different questions
  — the SHA pins the action's code, the input names the release it
  downloads — and SHA pinning removes the only other source of a version,
  since `github.action_ref` carries a tag only when the action is
  referenced by tag. The previous example showed the tag-only form, which
  is precisely the usage that breaks under the pinning practice
  recommended for an action running with `id-token: write`.
- Record the devbox PATH trap: a repository `bin/` prepended by
  `devbox.json` shadows the binary this action installs, so CI can
  silently exercise a local wrapper instead of the pinned release.

### Changed
- The no-version error names SHA pinning as the likely cause instead of
  suggesting a tag ref.

## [0.3.0]

### Added
- `.github/actions/setup-zcbctl` — a composite action that installs
  `zcbctl` and adds it to PATH, so a consuming repository needs no
  wrapper of its own. Version comes from the ref the action is pinned
  to, and the download is checksum-verified against the release manifest
  before anything is extracted.

## [0.2.0]

### Added
- `zcbctl` — the client for the token this broker mints. `zcbctl aws`
  emits AWS `credential_process` JSON, `zcbctl k8s` emits an
  `ExecCredential`. CI and humans differ only in how the Zitadel token is
  obtained (GitHub OIDC exchange vs. borrowing kubectl's existing
  session); everything after that is identical, so one identity serves
  Kubernetes and AWS with no second login and no stored credential.
- Released binaries and archives for `zcbctl` (linux/darwin, amd64/arm64)
  so consumers can install the client without the server.

### Documentation
- README rewritten for production use: architecture and trust chain, use
  cases, key rotation, failure-mode table, and limitations — including
  that Zitadel Actions cannot see the requesting client
  (zitadel/zitadel#9377), so any claim an action adds lands in every
  token the instance signs.

## [0.1.2]

### Added
- Initial release: `POST /exchange` — GitHub Actions OIDC token in,
  Zitadel machine-user token out. In-binary JWKS verification,
  IAM-StringLike subject mapping (the map is the policy), RFC 7523
  jwt-bearer minting with custodied Zitadel machine keys, Prometheus
  metrics, distroless nonroot image, Helm chart.
