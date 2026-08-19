# zitadel-ci-broker

Token broker for CI machine identities: exchanges a **GitHub Actions
OIDC token** for a **Zitadel machine-user token** — workload identity
federation as a service, until Zitadel ships it natively.

Ships with **`zcbctl`**, the client that turns the resulting token into
Kubernetes and AWS credentials for CI *and* for engineers.

---

## Why

CI workflows should hold **no stored secrets**. GitHub gives every
workflow a free, short-lived, signed OIDC identity token — but Zitadel's
token endpoint cannot consume it: the `jwt-bearer` grant (RFC 7523)
accepts only assertions signed by a machine user's own registered key,
and RFC 8693 token exchange accepts only Zitadel-issued subject tokens.
The broker fills exactly that gap and nothing more.

If Zitadel ships federated subject tokens (RFC 8693) or federated
credentials (RFC 7523 §2.1, as Azure does), this service dissolves by
design — see [Limitations](#limitations).

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
 GitHub Actions     │  broker                                  │
 ┌───────────────┐  │  1. verify  issuer JWKS, aud, exp        │
 │ workflow      │──┼─▶2. map     sub pattern → machine user   │──▶ Zitadel
 │ id-token:write│  │  3. sign    the user's custodied key      │   (jwt-bearer)
 └───────────────┘  │                                          │        │
         ▲          └──────────────────────────────────────────┘        │
         │                                                              ▼
         └────────────────── Zitadel machine-user token ────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
            Kubernetes API server                    AWS STS
            (OIDC IdP, aud = project)        (AssumeRoleWithWebIdentity)
```

**The exchange is the only privileged step.** Everything downstream is a
plain OIDC token: the API server validates it against the same issuer a
human's `kubectl` login uses, and STS validates it against an IAM OIDC
provider. Neither knows or cares that a broker was involved.

### Trust chain

| Link | What establishes trust |
|---|---|
| workflow → broker | GitHub's OIDC signature, verified in-binary against `token.actions.githubusercontent.com` JWKS |
| `sub` → machine user | the `identities` mapping — **this is the authorization policy** |
| broker → Zitadel | RFC 7523 `jwt-bearer`, signed with the machine user's custodied private key |
| token → Kubernetes | cluster's OIDC IdP config, `ClientId` = the Zitadel project |
| token → AWS | IAM OIDC provider whose ClientIDList contains the project |

---

## Use cases

### 0. Install it

In CI, one step — no wrapper to copy into each repository:

```yaml
- uses: truvity/zitadel-ci-broker/.github/actions/setup-zcbctl@v0.3.0
```

The action reads its version from the ref it is pinned to, verifies the
download against the release's checksum manifest, and adds `zcbctl` to
PATH. The calling job needs `permissions: id-token: write` — without it
the workflow cannot obtain the GitHub OIDC proof this broker exchanges.

On a laptop, install the released binary or `go install
github.com/truvity/zitadel-ci-broker/cmd/zcbctl@latest`.

### 1. CI reaches Kubernetes

The token is a bearer credential the API server accepts. Use it through
an `exec` credential plugin so nothing is written to disk and it refreshes
mid-run:

```yaml
users:
  - name: devel
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: zcbctl
        args: [k8s]
        interactiveMode: Never
```

### 2. CI reaches AWS

No AWS credentials, no `configure-aws-credentials`, no OIDC provider for
GitHub. The Zitadel token is exchanged directly by STS:

```ini
[profile devel]
region = eu-central-1
credential_process = zcbctl aws --role devel-zitadel-ci --account 123456789012
```

### 3. Engineers reach both — including engineers with no AWS account

`zcbctl` detects it is not in CI and borrows the session `kubectl`
already has, by running the **kubeconfig's own** `oidc-login` command:

```ini
[profile devel]
credential_process = zcbctl aws --context devel@oidc --role devel-zitadel-engineer --account 123456789012
```

This is the case that makes the broker more than a CI tool: an engineer
from a partner company who authenticates to Zitadel — but has no IAM
Identity Center account — gets AWS access with no additional provisioning.

---

## How it works

### Exchange

```
POST /exchange
Authorization: Bearer <GitHub Actions OIDC token>

→ 200 {"access_token": "...", "token_type": "Bearer", "expires_in": 43199}
→ 401 invalid/expired/wrong-audience token
→ 403 subject not mapped
```

From a workflow, without `zcbctl`:

```yaml
- run: |
    GH_JWT=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=zitadel-ci-broker" | jq -r .value)
    TOKEN=$(curl -sf -X POST https://broker.example.com/exchange \
      -H "Authorization: Bearer $GH_JWT" | jq -r .access_token)
```

### zcbctl

```
zcbctl aws --role <name|arn> [--account] [--region] [--session-name] [--context]
zcbctl k8s [--context]
```

Token acquisition branches on `ACTIONS_ID_TOKEN_REQUEST_URL`:

- **set** → CI: GitHub OIDC proof → `/exchange`
- **unset** → human: run the kubeconfig context's `oidc-login` command
  and take the token from its `ExecCredential`

Everything after that is identical. The AWS call is
`AssumeRoleWithWebIdentity`, which is **unsigned** — the token is the only
credential — so `zcbctl` needs no AWS SDK and no ambient AWS
configuration. That is deliberate: the tool must work for someone who has
no AWS account at all.

**Why the human path shells out to kubelogin.** kubelogin already owns the
browser flow, the local callback port, the token cache and silent refresh.
Reimplementing that would mean a second cache that can disagree with the
first, and a second browser prompt when it does. `zcbctl` reads the exec
arguments from the kubeconfig **verbatim**, because kubelogin derives its
cache key from issuer + client + scopes: one invented or reordered
argument misses the existing session and silently opens another login.

`zcbctl` refuses a context whose exec plugin is not `oidc-login` — an
`aws eks get-token` context mints an opaque EKS token that authenticates
to that cluster and is meaningless to STS. Accepting it silently surfaces
as *"token is not a JWT"* three layers from the cause.

---

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

The `:aud` scope is **load-bearing, not decoration**: it is what puts the
project into the token's `aud`, and both the Kubernetes API server and the
AWS IAM OIDC provider match on that value. A token minted without it
authenticates to nothing.

### Design notes

- **The mapping is the authorization policy** — a subject matching no row
  gets 403, and the refusal never echoes the map.
- The broker verifies tokens in-binary against the issuer's JWKS even when
  an edge proxy already did: a service whose safety depends on how it was
  fronted is a misconfiguration away from an open token mint.
- **Key custody**: the broker is the only holder of the machine-user keys
  (mount them as a Secret). The minting interface is pluggable so Zitadel's
  impersonation-based token exchange (one actor credential, no per-user
  keys) can replace custody without touching callers.

---

## Operations

### Deploy

A Helm chart ships at `oci://ghcr.io/truvity/charts/zitadel-ci-broker`;
images at `ghcr.io/truvity/zitadel-ci-broker` (distroless, nonroot). Put
the broker behind an authenticating gateway if you have one — the
in-binary verification then becomes defense in depth.

The broker must be reachable **from GitHub-hosted runners** if any consumer
runs there, which usually means a public hostname.

### Key rotation

Each mapped identity holds a Zitadel `KEY_TYPE_JSON` document. Rotating
one is: add the new key in Zitadel → update the mounted Secret → remove
the old key. The broker reads keys at startup, so a rolling restart is
part of the rotation.

### Failure modes

| Symptom | Cause |
|---|---|
| `401` from `/exchange` | wrong audience requested, or expired proof |
| `403` from `/exchange` | the workflow's `sub` matches no `identities` row |
| `403` **before** reaching the broker | an edge proxy filtering the client — see below |
| `InvalidIdentityToken` from STS | the token's audience is not in the IAM provider's ClientIDList |
| `AccessDenied` from STS | token valid, role trust refused it — a *different* problem |
| `token is not a JWT` from `zcbctl` | an opaque token: wrong kubeconfig context, or Zitadel not set to `ACCESS_TOKEN_TYPE_JWT` |

**Edge filtering**: a Cloudflare-fronted deployment rejects default library
user agents (`python-urllib`, `Go-http-client`) with a 403 the service never
sees. `zcbctl` sets an explicit `User-Agent`; any hand-rolled client must
do the same, or the failure looks like a broker outage.

### Observability

The `sub` of every refused exchange is worth logging at the caller: the
broker deliberately does not tell a client *why* it is unmapped, so the
workflow's own logs are where an onboarding mistake becomes visible.

---

## Limitations

**The client id is not available to Zitadel Actions.** Actions v2 payloads
(`preuserinfo`, `preaccesstoken`) carry the user, org and grants — but not
the requesting application. A token-enriching action therefore cannot vary
its output per client: any claim it adds lands in **every** token the
instance signs, including browser sessions whose tokens must fit in a
4096-byte cookie. Upstream request: [zitadel/zitadel#9377][9377], closed to
backlog. Plan claim additions accordingly.

**Machine tokens carry no `azp`.** A `jwt-bearer` token's `aud` contains
only the project — an application client id never enters it. This matters
for AWS: STS matches its ClientIDList against `azp` when present and `aud`
otherwise, so an IAM provider serving both CI and humans must register
**both** the project id and the human app's client id.

**No refresh.** The exchange returns an access token with a fixed lifetime
(~12h). There is no refresh token; a longer job re-exchanges. `zcbctl k8s`
reports an expiry one minute early so kubectl re-invokes it rather than
sending a token that expires mid-request.

**One audience per identity.** Scopes are per-`identities` row, so a
machine user that must reach two projects needs both `:aud` scopes listed.

**The action pins itself by ref.** `setup-zcbctl` derives the version
from `github.action_ref`, so `@v0.2.0` installs v0.2.0 and the two
cannot drift. Pinning the action to a branch therefore fails closed
rather than installing something unexpected.

**GitHub-only proofs.** The verification path is GitHub Actions OIDC. Other
CI systems would need their own issuer verification; the mapping and
minting layers are unaware of the source.

**The broker holds private keys.** Until Zitadel's impersonation-based
exchange replaces per-user keys, compromise of the broker is compromise of
every mapped machine identity. Treat its Secret and its host accordingly.

**It is designed to be deleted.** RFC 8693 federated subject tokens or RFC
7523 §2.1 federated credentials in Zitadel would make this service
redundant. Consumers depend on the *Zitadel token*, not on the broker, so
that removal is a deployment change rather than a migration.

[9377]: https://github.com/zitadel/zitadel/issues/9377

---

## License

[MIT](LICENSE)
