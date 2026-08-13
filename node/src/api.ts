/**
 * Vault Connect API client.
 *
 * Config resolution (priority):
 * 1. OP_CONNECT_HOST + OP_CONNECT_TOKEN (op CLI compat, manual token)
 * 2. OP_CONNECT_HOST + GitHub Actions OIDC env vars (CI, no stored secret)
 * 3. Shared Circles credential provider
 *
 * CLI flags --profile and --org override shared profile/default-context values.
 */

import { createCredentialProvider, isCredentialError } from "@circlesac/credentials"
import {
  completeRecovery as completeE2eeRecovery,
  downloadEncryptedFile,
  e2eeDoctor,
  handleApi,
  handleSecretsApi,
  startRecovery as startE2eeRecovery,
  uploadEncryptedFile,
  VaultApiError,
  type VaultConfig,
} from "./e2ee-client"

const DEFAULT_VAULT_HOST = "https://vault.circles.ac"
const DEV_VAULT_HOST = "https://vault.crcl.es"

const OIDC_TOKEN_LEEWAY_MS = 60_000 // refresh 1 min before exp

/** Detects GitHub Actions OIDC environment. Both vars are present together
 * when a workflow has `permissions: id-token: write`. */
export function hasGithubOidcEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  return !!(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
}

let _oidcCache: { audience: string; token: string; expMs: number } | null = null

/** Reset the OIDC token cache. Exported for tests. */
export function _resetOidcCache() {
  _oidcCache = null
}

function parseJwtExpMs(token: string): number {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf8")
    ) as { exp?: number }
    return payload.exp ? payload.exp * 1000 : 0
  } catch {
    return 0
  }
}

/** Fetch a GitHub Actions OIDC ID token for the given audience.
 * Returns null when not running inside a GitHub Actions workflow, or when
 * the OIDC request fails (caller falls back to other auth methods). */
export async function fetchGithubOidcToken(
  audience: string,
  env: NodeJS.ProcessEnv = process.env
): Promise<string | null> {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!requestUrl || !requestToken) return null

  if (_oidcCache && _oidcCache.audience === audience && Date.now() < _oidcCache.expMs - OIDC_TOKEN_LEEWAY_MS) {
    return _oidcCache.token
  }

  // GitHub's OIDC endpoint already carries query params; append audience.
  const sep = requestUrl.includes("?") ? "&" : "?"
  const fullUrl = `${requestUrl}${sep}audience=${encodeURIComponent(audience)}`

  try {
    const res = await fetch(fullUrl, {
      headers: { Authorization: `Bearer ${requestToken}` },
    })
    if (!res.ok) {
      console.error(`[ERROR] GitHub OIDC token request failed: ${res.status}`)
      return null
    }
    const data = (await res.json()) as { value?: string }
    if (!data.value) return null
    _oidcCache = { audience, token: data.value, expMs: parseJwtExpMs(data.value) }
    return data.value
  } catch (e) {
    console.error(`[ERROR] GitHub OIDC token fetch error: ${(e as Error).message}`)
    return null
  }
}

// Global overrides set by CLI flags
let _profileOverride: string | undefined
let _orgOverride: string | undefined
const orgAccessProbes = new Map<string, Promise<boolean>>()

export function setOverrides(opts: { profile?: string; org?: string }) {
  _profileOverride = opts.profile
  _orgOverride = opts.org
  orgAccessProbes.clear()
}

async function resolveCirclesCredential() {
  const provider = createCredentialProvider({
    ...(_profileOverride ? { profile: _profileOverride } : {}),
  })
  try {
    const credential = await provider.resolve()
    const profile = credential.source.type === "profile" ? await provider.getProfile() : undefined
    return { credential, profile }
  } catch (error) {
    if (isCredentialError(error)) {
      console.error(`Error: ${error.message}`)
      process.exit(1)
    }
    throw error
  }
}

/** Return the short-lived Circles credential selected by --profile. */
export async function getCirclesToken(): Promise<string> {
  return (await resolveCirclesCredential()).credential.value
}

export async function getConfig() {
  // 1. OP_CONNECT_* env vars (op CLI compat, manual token)
  if (process.env.OP_CONNECT_HOST && process.env.OP_CONNECT_TOKEN) {
    const url = new URL(process.env.OP_CONNECT_HOST)
    // Scope is encoded in the host path (op CLI has no --org): a path segment
    // = that org, a bare host = personal (lock #22).
    const org = url.pathname.replace(/^\//, "").replace(/\/$/, "") || null
    const baseUrl = org ? `${url.origin}/${org}` : url.origin
    return { baseUrl, token: process.env.OP_CONNECT_TOKEN, org }
  }

  // 2. OP_CONNECT_HOST + GitHub Actions OIDC env vars (CI)
  // No stored secret: the workflow has `id-token: write` permission and the
  // runner mints a short-lived JWT scoped to the configured audience.
  if (process.env.OP_CONNECT_HOST && hasGithubOidcEnv()) {
    const url = new URL(process.env.OP_CONNECT_HOST)
    const org = url.pathname.replace(/^\//, "").replace(/\/$/, "") || null
    const baseUrl = org ? `${url.origin}/${org}` : url.origin
    const audience = process.env.OP_CONNECT_AUDIENCE || baseUrl
    const oidcToken = await fetchGithubOidcToken(audience)
    if (oidcToken) {
      return { baseUrl, token: oidcToken, org }
    }
    console.error("[ERROR] GitHub OIDC env vars set but token fetch failed")
    process.exit(1)
  }

  // 3. Shared Circles credential provider. This resolves canonical and legacy
  // env vars, the shared current profile, legacy profiles, and direct refresh
  // without requiring the crcl executable.
  const { credential, profile } = await resolveCirclesCredential()

  // Scope (lock #22): personal by default. An org is targeted only when
  // explicitly requested via --org or CRCL_ORG. Stored profile orgs do not
  // auto-escalate. OIDC (CI) above always carries an org.
  const org = _orgOverride || process.env.CRCL_ORG || null

  // An environment credential has no endpoint metadata and therefore targets
  // production. Profile credentials retain their configured environment.
  const isDevProfile = profile?.config.apiUrl?.includes("-dev") || profile?.config.authUrl?.includes("-dev")
  const host = isDevProfile ? DEV_VAULT_HOST : DEFAULT_VAULT_HOST
  const baseUrl = org ? `${host}/${org}` : host
  return { baseUrl, token: credential.value, org }
}

async function canAccessOrg(config: VaultConfig, org: string): Promise<boolean> {
  const key = `${config.baseUrl}\n${org}`
  let probe = orgAccessProbes.get(key)
  if (!probe) {
    probe = (async () => {
      const res = await fetch(`${config.baseUrl}/${encodeURIComponent(org)}/v1/status`, {
        headers: { Authorization: `Bearer ${config.token}` },
      })
      if (res.ok) return true
      const text = await res.text()
      let message = text
      try {
        message = JSON.parse(text).message || text
      } catch {}
      if (
        res.status === 403
        && (message === "Org not found" || message === "Not a member of this organization")
      ) {
        return false
      }
      throw new VaultApiError(res.status, message)
    })()
    orgAccessProbes.set(key, probe)
  }
  try {
    return await probe
  } catch (error) {
    orgAccessProbes.delete(key)
    throw error
  }
}

export async function getConfigForVltOwner(owner: string): Promise<VaultConfig> {
  const normalizedOwner = owner.toLowerCase()
  const config = await getConfig()
  if (config.org) {
    if (config.org.toLowerCase() !== normalizedOwner) {
      throw new Error(
        `vlt:// owner '${normalizedOwner}' does not match selected org '${config.org}'`
      )
    }
    return config
  }
  const hasFixedConnectScope = !!(
    process.env.OP_CONNECT_HOST
    && (process.env.OP_CONNECT_TOKEN || hasGithubOidcEnv())
  )
  if (hasFixedConnectScope || !(await canAccessOrg(config, normalizedOwner))) {
    return config
  }
  return {
    ...config,
    baseUrl: `${config.baseUrl}/${normalizedOwner}`,
    org: normalizedOwner,
  }
}

/** Flat secrets API (vlt:// surface). Shares the unified scope of getConfig:
 * personal by default, org via --org / CRCL_ORG (lock #22). */
export async function secretsApi<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  try {
    return await rawSecretsApi<T>(path, opts)
  } catch (error) {
    return fail(error)
  }
}

export async function secretsApiForOwner<T = unknown>(
  owner: string,
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  try {
    return await rawSecretsApiWithConfig<T>(await getConfigForVltOwner(owner), path, opts)
  } catch (error) {
    return fail(error)
  }
}

export async function api<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  try {
    return await rawApi<T>(path, opts)
  } catch (error) {
    return fail(error)
  }
}

export async function rawSecretsApi<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  return rawSecretsApiWithConfig<T>(await getConfig(), path, opts)
}

async function rawSecretsApiWithConfig<T>(
  config: VaultConfig,
  path: string,
  opts: { method?: string; body?: unknown }
): Promise<T> {
  const translated = await handleSecretsApi<T>(config, path, fetchGithubOidcToken)
  if (translated.handled) return translated.value as T
  return request<T>(`${config.baseUrl}${path}`, config.token, opts)
}

export async function rawApi<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  const config = await getConfig()
  const translated = await handleApi<T>(config, path, opts, fetchGithubOidcToken)
  if (translated.handled) return translated.value as T
  return request<T>(`${config.baseUrl}${path}`, config.token, opts)
}

function fail(error: unknown): never {
  if (error instanceof VaultApiError) {
    console.error(`[ERROR] ${error.status}: ${error.message}`)
  } else {
    console.error(`[ERROR] ${(error as Error).message}`)
  }
  process.exit(1)
}

/** Like api(), but returns null on a non-OK response instead of exiting —
 * for best-effort lookups (e.g. OIDC callers can't list grants). */
export async function apiOptional<T = unknown>(path: string): Promise<T | null> {
  const { baseUrl, token } = await getConfig()
  try {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!res.ok) return null
    return (await res.json()) as T
  } catch {
    return null
  }
}

async function request<T = unknown>(
  url: string,
  token: string,
  opts: { method?: string; body?: unknown } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  }
  if (opts.body) {
    headers["Content-Type"] = "application/json"
  }

  const res = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  })

  if (!res.ok) {
    const text = await res.text()
    let message: string
    try {
      message = JSON.parse(text).message || text
    } catch {
      message = text
    }
    throw new VaultApiError(res.status, message)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** Resolve vault by name or ID */
export async function resolveVault(nameOrId: string): Promise<string> {
  if (/^[0-9a-hjkmnp-tv-z]{26}$/.test(nameOrId)) return nameOrId
  type Vault = { id: string; name: string }
  const vaults = await api<Vault[]>("/v1/vaults")
  const match = vaults.find(
    (v) => v.id === nameOrId || v.name.toLowerCase() === nameOrId.toLowerCase()
  )
  if (!match) {
    console.error(`[ERROR] Vault "${nameOrId}" not found`)
    process.exit(1)
  }
  return match.id
}

/** Resolve item by name or ID within a vault */
export async function resolveItem(
  vaultId: string,
  nameOrId: string
): Promise<string> {
  if (/^[0-9a-hjkmnp-tv-z]{26}$/.test(nameOrId)) return nameOrId
  const item = await api<{ id: string }>(`/v1/vaults/${vaultId}/items/resolve`, {
    method: "POST",
    body: { title: nameOrId },
  })
  return item.id
}

export async function uploadFile(
  vaultId: string,
  itemId: string,
  name: string,
  contentType: string,
  content: Uint8Array
) {
  try {
    return await uploadEncryptedFile(
      await getConfig(),
      vaultId,
      itemId,
      name,
      contentType,
      content,
      fetchGithubOidcToken
    )
  } catch (error) {
    return fail(error)
  }
}

export async function downloadFile(vaultId: string, itemId: string, fileId: string) {
  try {
    return await downloadEncryptedFile(await getConfig(), vaultId, itemId, fileId, fetchGithubOidcToken)
  } catch (error) {
    return fail(error)
  }
}

export async function doctorE2ee() {
  try {
    return await e2eeDoctor(await getConfig())
  } catch (error) {
    return fail(error)
  }
}

export async function startRecovery() {
  try {
    return await startE2eeRecovery(await getConfig())
  } catch (error) {
    return fail(error)
  }
}

export async function completeRecovery(emailCode: string, recoveryCode: string) {
  try {
    return await completeE2eeRecovery(await getConfig(), emailCode, recoveryCode)
  } catch (error) {
    return fail(error)
  }
}
