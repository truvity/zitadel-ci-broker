# Changelog

## [Unreleased]

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
