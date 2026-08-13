# zitadel-ci-broker

Token broker for CI machine identities: exchanges a **GitHub Actions
OIDC token** for a **Zitadel machine-user token** — workload identity
federation as a service, until Zitadel ships it natively.

## Why

CI workflows should hold **no stored secrets**. GitHub gives every
workflow a free, short-lived, signed OIDC identity token — but Zitadel's
token endpoint cannot consume it: the `jwt-bearer` grant (RFC 7523)
accepts only assertions signed by a machine user's own registered key,
and RFC 8693 token exchange accepts only Zitadel-issued subject tokens.
The broker fills exactly that gap and nothing more:

```
workflow ──GitHub OIDC token──▶ broker ──jwt-bearer──▶ Zitadel ──token──▶ workflow
                                  │
                                  ├─ verify: issuer JWKS, audience, expiry
                                  ├─ map:    sub pattern → machine user (the allowlist)
                                  └─ sign:   the user's custodied key
```

If Zitadel ships federated subject tokens (RFC 8693) or federated
credentials (RFC 7523 §2.1, as Azure does), this service dissolves by
design.

## Exchange

```
POST /exchange
Authorization: Bearer <GitHub Actions OIDC token>

→ 200 {"access_token": "...", "token_type": "Bearer", "expires_in": 43199}
→ 401 invalid/expired/wrong-audience token
→ 403 subject not mapped
```

From a workflow:

```yaml
- run: |
    GH_JWT=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=zitadel-ci-broker" | jq -r .value)
    TOKEN=$(curl -sf -X POST https://broker.example.com/exchange \
      -H "Authorization: Bearer $GH_JWT" | jq -r .access_token)
```

## Configuration

```yaml
zitadel:
  domain: https://auth.example.com
github:
  audience: zitadel-ci-broker   # the workflow must request this audience
identities:
  - subjects:                   # IAM-StringLike patterns; the map IS the policy
      - "repo:my-org/my-repo:ref:refs/heads/*"
      - "repo:my-org/my-repo:pull_request"
    user: ci-my-org-my-repo-preview
    keyFile: /keys/ci-my-org-my-repo-preview   # Zitadel KEY_TYPE_JSON document
    scopes:
      - openid
      - urn:zitadel:iam:org:project:id:<project-id>:aud
```

Design notes:

- **The mapping is the authorization policy** — a subject matching no
  row gets 403, and the refusal never echoes the map.
- The broker verifies tokens in-binary against the issuer's JWKS even
  when an edge proxy already did: a service whose safety depends on how
  it was fronted is a misconfiguration away from an open token mint.
- Key custody: the broker is the only holder of the machine-user keys
  (mount them as a Secret). The minting interface is pluggable so
  Zitadel's impersonation-based token exchange (one actor credential,
  no per-user keys) can replace custody without touching callers.

## Deploy

A Helm chart ships at `oci://ghcr.io/truvity/charts/zitadel-ci-broker`;
images at `ghcr.io/truvity/zitadel-ci-broker` (distroless, nonroot).
Put the broker behind an authenticating gateway if you have one — the
in-binary verification then becomes defense in depth.

## License

[MIT](LICENSE)
