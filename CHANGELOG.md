# Changelog

## [Unreleased]

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
