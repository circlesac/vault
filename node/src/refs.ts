// Secret reference parsing + substitution — pure functions, no I/O.
//
// Two address surfaces over one store (vault RFC #6; vlt:// grammar lock #22):
//   op://<vault>/<item>/<field>                  — 1Password-compatible, exact
//   vlt://<provider>/<owner>[/<repo>]/<NAME>      — github coordinate, inherits
//
// vlt:// uses the same slash grammar as op:// (no '#'): NAME is the last
// segment, the leading github coordinate is the vault. op:// can't name that
// vault (its name has '/'), which is why vlt:// exists. NAME uses uppercase
// letters, digits, underscores, and hyphens; NO escaping; out-of-charset input
// is rejected.

export type OpRef = { scheme: "op"; vault: string; item: string; field: string }
export type CcvltRef = {
  scheme: "cvlt"
  provider: string
  owner: string
  repo: string | null
  name: string
}
export type SecretRef = OpRef | CcvltRef

export type ParseResult =
  | { ok: true; ref: SecretRef }
  | { ok: false; message: string }

// op:// — preserves the historical behavior exactly: first three slash
// segments, query suffix ignored, extra segments ignored.
const OP_RE = /^op:\/\/([^/]+)\/([^/]+)\/([^/?]+)/

const CVLT_PROVIDERS = new Set(["github.com"])
const OWNER_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/
const REPO_RE = /^[a-zA-Z0-9_.-]{1,100}$/
const NAME_RE = /^[A-Z_][A-Z0-9_-]{0,199}$/

export function parseRef(ref: string): ParseResult {
  if (ref.startsWith("op://")) {
    const match = ref.match(OP_RE)
    if (!match) {
      return { ok: false, message: "Expected format: op://<vault>/<item>/<field>" }
    }
    return {
      ok: true,
      ref: { scheme: "op", vault: match[1]!, item: match[2]!, field: match[3]! },
    }
  }

  if (ref.startsWith("vlt://")) {
    const path = ref.slice("vlt://".length)
    if (path.includes("#")) {
      return { ok: false, message: "vlt:// uses '/'-separated segments, not '#' (e.g. vlt://github.com/owner/repo/NAME)" }
    }
    const segments = path.split("/")
    // <provider>/<owner>/<NAME> (3) or <provider>/<owner>/<repo>/<NAME> (4)
    if (segments.length < 3 || segments.length > 4) {
      return { ok: false, message: "Expected format: vlt://<provider>/<owner>[/<repo>]/<NAME>" }
    }
    const provider = segments[0]!
    const owner = segments[1]!
    const repo = segments.length === 4 ? segments[2]! : undefined
    const name = segments[segments.length - 1]!
    if (!CVLT_PROVIDERS.has(provider)) {
      return { ok: false, message: `Unsupported provider: ${provider}` }
    }
    if (!OWNER_RE.test(owner)) {
      return { ok: false, message: "Invalid owner (GitHub owner charset)" }
    }
    if (repo !== undefined && !REPO_RE.test(repo)) {
      return { ok: false, message: "Invalid repo (GitHub repo charset)" }
    }
    if (!NAME_RE.test(name)) {
      return { ok: false, message: "Invalid NAME (uppercase letters, digits, underscores, and hyphens; no digit start)" }
    }
    return {
      ok: true,
      ref: {
        scheme: "cvlt",
        provider,
        owner: owner.toLowerCase(),
        repo: repo !== undefined ? repo.toLowerCase() : null,
        name,
      },
    }
  }

  return { ok: false, message: "Reference must start with op:// or vlt://" }
}

export function isSecretRef(value: string): boolean {
  return value.startsWith("op://") || value.startsWith("vlt://")
}

export type VaultCoordinate = { provider: string; owner: string; repo: string | null }

/** Coordinate-shaped vault name (`github.com/<owner>[/<repo>]`, lock #20/#21)
 * vs a free-form op:// vault name. Full coordinate including provider is
 * canonical — the provider prefix makes the distinction syntactic. */
export function parseVaultCoordinate(name: string): VaultCoordinate | null {
  const segments = name.split("/")
  if (segments.length < 2 || segments.length > 3) return null
  const [provider, owner, repo] = segments as [string, string, string | undefined]
  if (!CVLT_PROVIDERS.has(provider)) return null
  if (!OWNER_RE.test(owner)) return null
  if (repo !== undefined && !REPO_RE.test(repo)) return null
  return { provider, owner: owner.toLowerCase(), repo: repo !== undefined ? repo.toLowerCase() : null }
}

export type Resolver = (ref: string) => Promise<string>

/** Replace every {{op://...}} / {{vlt://...}} template reference. */
export async function injectTemplate(template: string, resolve: Resolver): Promise<string> {
  const refs = [...template.matchAll(/\{\{((?:op|vlt):\/\/[^}]+)\}\}/g)]
  const values = new Map(await Promise.all(
    [...new Set(refs.map((match) => match[1]!))].map(async (ref) => [ref, await resolve(ref)] as const)
  ))
  return template.replace(
    /\{\{((?:op|vlt):\/\/[^}]+)\}\}/g,
    (_match, ref: string) => values.get(ref)!
  )
}

/** Parse an env file (KEY=value lines; #-comments and blanks skipped).
 * Values may be secret references or plain strings — callers decide. */
export function parseEnvFile(content: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const raw of content.split("\n")) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    const eqIdx = line.indexOf("=")
    if (eqIdx <= 0) continue
    out[line.slice(0, eqIdx).trim()] = line.slice(eqIdx + 1).trim()
  }
  return out
}

/** Build the child-process env for `cvlt run`: resolves reference-valued
 * entries from the env file and the parent env; plain values pass through. */
export async function buildRunEnv(
  parentEnv: Record<string, string | undefined>,
  envFileContent: string | null,
  resolve: Resolver
): Promise<Record<string, string | undefined>> {
  const env = {
    ...parentEnv,
    ...(envFileContent === null ? {} : parseEnvFile(envFileContent)),
  }
  const refs = [...new Set(Object.values(env).filter(
    (value): value is string => !!value && isSecretRef(value)
  ))]
  const values = new Map(await Promise.all(
    refs.map(async (ref) => [ref, await resolve(ref)] as const)
  ))
  for (const [key, value] of Object.entries(env)) {
    if (value && isSecretRef(value)) env[key] = values.get(value)!
  }
  return env
}
