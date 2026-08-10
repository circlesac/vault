# cvlt

[![npm](https://img.shields.io/npm/v/@circlesac/vlt-cli.svg)](https://www.npmjs.com/package/@circlesac/vlt-cli)

`cvlt` is the official CLI for [Circles Vault](https://github.com/circlesac/vault), with two parallel address surfaces:

- **`op://<vault>/<item>/<field>`** — 1Password-style. The `cvlt read`, `inject`, and `run` workflows preserve the familiar command and reference shape while encrypting locally.
- **`vlt://<provider>/<owner>[/<repo>]/<NAME>`** — flat GitHub-Secrets-style key→value secrets, addressed by GitHub coordinates. The repo segment selects the scope: present → project secret, absent → owner-global. Designed to replace GitHub Actions secrets (the coordinate is identical to the OIDC `repository` claim).

`cvlt read`, `cvlt inject`, and `cvlt run` accept both schemes anywhere a reference appears.

## Install

```bash
# macOS / Linux via Homebrew
brew install circlesac/tap/cvlt

# Any Node.js environment (works on GitHub Actions ubuntu-latest)
npm install -g @circlesac/vlt-cli

# Static binaries (no Node required)
# Download from https://github.com/circlesac/vault/releases/latest
```

## Authentication

`cvlt` resolves credentials in this order:

1. **`OP_CONNECT_HOST` + `OP_CONNECT_TOKEN`** — drop-in for `op` CLI; useful when you already have a token.
2. **`OP_CONNECT_HOST` + GitHub Actions OIDC** — if `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` are present (workflow has `id-token: write`), `cvlt` fetches a short-lived OIDC token automatically. No stored secrets.
3. **Shared Circles credentials** (`~/.crcl/config` + `~/.crcl/credentials`) — interactive user. The first `crcl login` establishes the shared current profile; later identities are selected explicitly with `crcl use`. Legacy `~/.config/crcl` profiles remain readable through automatic migration.

`cvlt whoami` shows the resolved host + account (`personal` by default, or `org:<slug>` with `--org`/`CRCL_ORG`).

## Common commands

### Read a secret

```bash
cvlt read "op://my-vault/db-credentials/password"
cvlt read -n "op://my-vault/db-credentials/password"   # no trailing newline
cvlt read -o /tmp/password "op://..."                  # write to file
```

### Inject secrets into a template

```bash
# template.env
DB_HOST={{op://my-vault/db-credentials/host}}
DB_PASS={{op://my-vault/db-credentials/password}}

# Inject and write
cvlt inject -i template.env -o .env

# Or pipe
cat template.env | cvlt inject > .env
```

### Run a command with secrets injected as env vars

```bash
DB_PASS="op://my-vault/db-credentials/password" cvlt run -- ./deploy.sh

# op run idiom: keep references in a committed env file (references are not secrets)
cvlt run --env-file=.cvlt.env -- ./deploy.sh
```

```bash
# .cvlt.env — safe to commit; values are fetched at runtime
DB_PASSWORD=vlt://github.com/acme/api/DB_PASSWORD
OPENAI_KEY=vlt://github.com/acme/OPENAI_KEY
ACCOUNT_PASSWORD=op://my-vault/db-credentials/password
```

`cvlt run` resolves `op://` / `vlt://` references found in `--env-file` entries and the process env, then exec's the command with the actual values.

### Use the 1Password `op` CLI

Run the localhost-only Connect bridge in one terminal:

```bash
cvlt connect
```

Copy the printed `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` exports into another terminal. The standard 1Password CLI can then read Circles Vault without a separate account key argument:

```bash
op read "op://my-vault/db-credentials/password"
op inject --in-file config.yml.tpl
DB_PASS="op://my-vault/db-credentials/password" op run --no-masking -- printenv DB_PASS
```

The bridge decrypts locally with this installation's protected key and stops accepting requests when `cvlt connect` exits.

### Manage vaults

```bash
cvlt vault list
cvlt vault create "production"
cvlt vault edit "production" --name "prod-secrets"
cvlt vault delete "old-vault"
```

### Manage items

```bash
cvlt item create --vault prod-secrets --category login --title "DB" username=admin password=secret
cvlt item list --vault prod-secrets
cvlt item get "DB" --vault prod-secrets --format json
cvlt item edit "DB" --vault prod-secrets password=newpass
cvlt item edit "DB" --vault prod-secrets 'token[password]' # change type, preserve value
cvlt item delete "DB" --vault prod-secrets
cvlt item move "DB" --current-vault staging --destination-vault prod-secrets
```

### Documents

```bash
cvlt document create ./cert.pem --vault prod-secrets --title "TLS Cert"
cvlt document list --vault prod-secrets
cvlt document get "TLS Cert" --vault prod-secrets -o ./cert.pem
```

### Client encryption and recovery

Vault content is encrypted locally before upload. The service receives the encrypted representation required by the public client protocol.

```bash
cvlt doctor # account encryption, installation key, and GitHub OIDC KMS state
```

The first interactive initialization prints a high-entropy recovery code once. Store it outside Vault. The installation private key is saved in macOS Keychain, Windows DPAPI, Linux Secret Service, or a passphrase-encrypted local file when no OS store exists.

On a new machine, run a fresh `crcl login`, then:

```bash
cvlt recover start --org circlesac
cvlt recover complete 12345678 --org circlesac
```

The second command prompts for the recovery code without placing it in shell history. A successful recovery replaces the previous installation credentials and prints a new recovery code once.

### GitHub-coordinate secrets (vlt://)

A secret is just an op:// **item** (there's no separate "secret" store or verb). What's special about a vault named like a GitHub coordinate — `github.com/<owner>[/<repo>]` — is that it's addressed by the **`vlt://` reference scheme**, which exists for two reasons `op://` can't cover:

1. **Coordinate names contain `/`.** An `op://<vault>/<item>/<field>` reference splits on `/`, so it can't name a vault like `github.com/acme/api` (the slashes collide). `vlt://github.com/<owner>[/<repo>]/<NAME>` knows the structure — `<NAME>` is the last segment, the leading github coordinate is the vault — so it parses unambiguously, no escaping.
2. **Inheritance.** Reads cascade `project > global` (repo→owner), like GitHub Actions repo/org secrets.

- `vlt://github.com/<owner>/<repo>/<NAME>` — project; falls back to the owner if absent
- `vlt://github.com/<owner>/<NAME>` — owner-global
- NAME charset is GitHub-isomorphic (`[A-Z0-9_]`, no digit start, no `GITHUB_` prefix)

The item itself is still managed with the op `item`/`vault` verbs — those take the coordinate as a `--vault` **name** (a flag value, not an `op://` reference, so the slashes are fine).

```bash
# Register the coordinate vault (+ CI grant for a repo coordinate; org-scoped → --org)
cvlt vault create github.com/acme/api --org acme

# Write a secret = create/edit an item in that vault (--vault takes the name)
cvlt item create --vault github.com/acme/api --title DB_PASSWORD 'value[password]=s3cret'
cvlt item edit DB_PASSWORD --vault github.com/acme/api 'value[password]=rotated'

# Read by reference — vlt:// handles the coordinate + inherits (project→owner)
cvlt read "vlt://github.com/acme/api/DB_PASSWORD"          # infers accessible org acme; cascades to github.com/acme if absent

# List / delete = op item verbs (coordinate as --vault name)
cvlt item list --vault github.com/acme/api
cvlt item delete DB_PASSWORD --vault github.com/acme/api
```

**Scope: personal by default, except `vlt://`.** General commands and `op://` references target your personal account unless you select an org with `--org <slug>` (or `CRCL_ORG`). A `vlt://github.com/<owner>/...` read automatically targets `<owner>` when it is an org accessible to the current Circles credential; otherwise it keeps the personal fallback. An explicit org must match the reference owner, and `run`/`inject` resolve mixed owners independently. CI via GitHub OIDC already has its org fixed by `OP_CONNECT_HOST`.

### Registering repos for CI access (operator-only)

`cvlt vault create <coordinate>` creates the op:// vault that stores the secrets; for a **repo** coordinate it also records the OIDC grant that lets that repo's CI read it (**creating it is the consent**). Grants are org-scoped, so pass `--org <owner>`. Once per repo:

```bash
cvlt vault create github.com/circlesac/my-app --org circlesac
cvlt vault create github.com/circlesac/my-app --org circlesac --ci-write --env production

cvlt vault get github.com/circlesac/my-app --org circlesac     # registration + secret count
cvlt vault delete github.com/circlesac/my-app --org circlesac  # revokes CI access; items remain
```

Owner-global (`github.com/circlesac`) needs no grant — every registered repo of that owner reads it via `project > global`, and org members write to it with `cvlt item create --vault github.com/circlesac --org circlesac …`.

The advanced `cvlt oidc grant create|list|get|edit|delete` commands remain for op://-vault-scoped or org-wildcard (`owner/*`) grants.

`vault create / edit / delete`, `oidc grant *`, and `whoami` require operator (user JWT) auth. OIDC tokens from GitHub Actions are scoped to data-plane operations (read secrets/items, write if allowed) and cannot manage vaults or grants regardless of role.

## GitHub Actions workflow

After registering the repo once, a workflow needs zero stored secrets:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      OP_CONNECT_HOST: https://vault.circles.ac/<your-org>
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g @circlesac/vlt-cli
      - run: cvlt run -- ./deploy.sh
```

`cvlt` detects the runner's `ACTIONS_ID_TOKEN_REQUEST_URL` / `_TOKEN` env vars, mints a GitHub OIDC token with the right audience, and sends it to Vault. The server verifies GitHub's signature, matches the claims (`repository`, `environment`, `ref`) against the grant ACL, and serves the request.

For vlt:// secrets the grant's `repository` doubles as the coordinate: a granted workflow can read its own project secrets plus that owner's globals — no other coordinate, regardless of what it asks for.

### Composite action

The repo ships a composite action that installs `cvlt` and sets the endpoint:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: circlesac/vault/action@main
    with:
      host: https://vault.circles.ac/<your-org>
  - run: cvlt run --env-file=.cvlt.env -- ./deploy.sh
```

With `export-env: true` the action resolves `env-file` entries into `$GITHUB_ENV` (each value masked via `::add-mask::` first), so later steps can use `${{ env.NAME }}` — one word away from GitHub-native `${{ secrets.NAME }}`:

```yaml
  - uses: circlesac/vault/action@main
    with:
      host: https://vault.circles.ac/<your-org>
      env-file: .cvlt.env
      export-env: "true"
  - run: ./deploy.sh                # $DB_PASSWORD available to the whole job
```

`cvlt run` keeps secrets scoped to the child process (narrower exposure, recommended); `export-env` trades that for job-wide convenience.

## Profile / org overrides

```bash
cvlt vault list                       # shared current profile, personal account
cvlt vault list --profile dev         # explicitly selected Circles profile
cvlt vault list --org other-org       # different org slug
```

## Node SDK

Install the SDK independently from the CLI:

```sh
npm install @circlesac/vault
```

The SDK package exposes the same E2EE and OS credential-store implementation
used by the CLI. Applications can read Vault values without spawning `cvlt`:

```js
import { createVaultClient } from "@circlesac/vault"

const vault = createVaultClient()
const password = await vault.read("op://personal/Modusign/password")
```

The device key remains in macOS Keychain, Linux Secret Service, or Windows
DPAPI. Account credentials and decrypted Vault values are not copied into the
application's configuration directory.

The language-neutral client contract is documented in [`SDK.md`](SDK.md), and
the native Go SDK is published from [`go/`](go/README.md).

Installing `@circlesac/vault` never downloads the native CLI. The separate
`@circlesac/vlt-cli` package installs the `cvlt` shim and platform binary.
