# Circles Vault client contract

This repository is the public reference implementation and contract for
Circles Vault clients. The hosted Vault service remains separate.

## Language implementations

| Runtime | Location or distribution | Status |
| --- | --- | --- |
| Node.js | `@circlesac/vlt-cli/client` | Reference implementation |
| Go | `go/` in this repository | Read-only `op://` client (v0.1.x) |

New language implementations belong in this repository when the ecosystem
supports a subdirectory package or module. They must not shell out to `cvlt`
and must execute the same contract cases. A separate repository is only needed
when a language registry requires the repository root to be the package root.

## Required behavior

Every implementation must:

1. Resolve `op://<vault>/<item>/<field>` references with case-insensitive vault
   names and exact field label, ID, or purpose matching.
2. Resolve `vlt://github.com/<owner>[/<repo>]/<NAME>` references using the
   canonical grammar implemented by `node/src/refs.ts`.
3. Resolve authentication in this order: explicit Connect environment,
   GitHub Actions OIDC, then the shared Circles credential provider.
4. Encrypt and decrypt item content on the client and never send plaintext
   item names, fields, or values to an E2EE Vault endpoint.
5. Store the installation private key in the operating-system credential
   store: macOS Keychain, Linux Secret Service, or Windows DPAPI.
6. Use an encrypted local key file only when the OS credential store is
   unavailable. The fallback file and its parent directory must use restrictive
   permissions where the filesystem supports them.
7. Return structured errors to SDK callers. A library must not print secrets,
   terminate the host process, or require the `cvlt` executable.

## Installation lifecycle

An installation key is scoped to a Vault **origin** (scheme and host), not to an
account. One key serves the personal account and every organization selected on
that deployment.

- **First use.** An uninitialized account is bootstrapped by the first
  interactive write: the client generates the account key, wraps it to its own
  public key, creates the recovery envelope, and prints the recovery code once.
- **Load or create.** Any implementation that needs an installation key must
  reuse the origin's existing key and generate one only when the origin has no
  key. Overwriting the slot breaks every account already registered to it, so
  key rotation must be a separate, coordinated operation.
- **Enrollment.** A fresh installation emits a public enrollment request; an
  already registered installation approves it.
- **Recovery.** `recover` is the lost-all-installations path. It revokes every
  registered installation and rotates the recovery envelope.

### Client ID

The client ID is the canonical public-key fingerprint: the base64url SHA-256 of
the public JWK serialized with its properties in lexicographic order and no
whitespace. Implementations must canonicalize before hashing, because WebCrypto
runtimes export JWK properties in different orders.

The public-key contract is RSA-OAEP, 3072-bit modulus, SHA-256, exponent 65537,
public operations only, and exactly the properties `alg`, `e`, `ext`,
`key_ops`, `kty`, `n`. Private RSA parameters and extra properties are rejected.

### Enrollment request

Deterministic, versioned, base64url-encoded JSON with these properties in this
order — `name` is omitted when absent:

```json
{
  "version": 1,
  "origin": "https://vault.example",
  "account": "org:1",
  "client_id": "<canonical public-key fingerprint>",
  "public_key": { "alg": "RSA-OAEP-256", "e": "AQAB", "ext": true, "key_ops": ["encrypt"], "kty": "RSA", "n": "<modulus>" },
  "platform": "linux",
  "name": "example-workstation"
}
```

It is public registration material, never a bearer credential, and must never
carry a private key, a raw or wrapped account key, a recovery code, an access
token, decrypted Vault content, or a credential-file path. An approver must
reject any request whose `client_id` is not the fingerprint of the enclosed
`public_key`, whose `origin` is not its own normalized Vault origin, or whose
`account` is not the canonical account the service returned for it. Approval
also requires displaying the fingerprint and taking an explicit confirmation.

### Client-management possession proof

`GET /v1/clients`, `POST /v1/clients`, and `DELETE /v1/clients/:clientId`
require a signed-in user **and** proof that the caller holds an active
installation's private key.

1. `POST /v1/clients/challenges` with `{ client_id, method, path, body_sha256 }`
   under the user credential and the `X-CVLT-Client-ID` header.
2. The service returns `{ id, ciphertext, expires_at }`, where `ciphertext` is
   RSA-OAEP/SHA-256 encrypted to the registered public key with the label
   `cvlt:v1:client-management:<account>:<challenge-id>`.
3. The client decrypts locally and sends `X-CVLT-Client-ID`,
   `X-CVLT-Challenge-ID`, and `X-CVLT-Challenge-Proof` on the bound request.

### Installation identity on data routes

Send `X-CVLT-Client-ID` on ordinary signed-in data requests too — `/v1/vaults`
and its nested item and file routes, plus `/v1/coordinates` and
`/v1/coordinates/read` — not only on `/v1/status`. The service rechecks the named
installation against the selected account on every such request, so a revoked
installation stops reading even while the caller still holds the unwrapped
account key. Match on the request **pathname**: `/v1/coordinates` is always
called with a query string, and matching the whole path silently drops the
header. GitHub Actions OIDC callers hold no installation key and send no header.

`path` is the exact wire pathname including the organization prefix, excluding
query string and fragment. `body_sha256` is the lowercase hexadecimal SHA-256 of
the exact request-body bytes; `GET` and `DELETE` use the digest of zero bytes,
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. A `POST`
body must be serialized once and the same bytes hashed and sent — neither side
may hash re-serialized JSON. Proofs are single-use, expire in five minutes, and
must never be logged.

## Public API baseline

Language implementations expose equivalent operations even when naming follows
language conventions:

```text
CreateClient(options)
Client.Read(reference) -> string
Client.GetItem(vault, item) -> Item
```

The Node reference spelling is:

```js
import { createVaultClient } from "@circlesac/vlt-cli/client"

const vault = createVaultClient()
await vault.read("op://personal/example-service/password")
await vault.getItem("personal", "example-service")
```

## Compatibility

Contract changes must remain readable by older clients or carry an explicit
format version and migration path. Node and Go implementations must share
language-neutral fixtures before the Go package is considered supported.
