import {
  decodeBase64,
  decryptJson,
  encodeBase64,
  encryptJson,
  itemLocator,
  parseKmsPlaintext,
  type AesEnvelope,
  type ContentEnvelope,
  type RsaEnvelope,
} from "./e2ee-crypto.js"
import { filterVaults } from "./connect-filters.js"

export type VaultFetcher = {
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>
}

export type GoogleServiceAccountCredentials = {
  client_email: string
  private_key: string
  token_uri?: string
}

export type VaultKeyUnwrapper = (input: {
  vaultId: string
  wrappedVaultKey: RsaEnvelope
  keyVersion: string
}) => Promise<Uint8Array>

export type ConnectClientOptions = {
  fetcher?: VaultFetcher
  baseUrl?: string
  googleFetch?: typeof fetch
  googleServiceAccount?: string | GoogleServiceAccountCredentials
  unwrapVaultKey?: VaultKeyUnwrapper
}

type Status = {
  kms: { key_version: string | null }
}

type VaultRow = {
  id: string
  attribute_version: number
  content_version: number
  created_at: string
  updated_at: string
  items: number
  content_mode?: "e2ee" | "plain"
  integration_coordinate?: string | null
  name?: string
  description?: string
  type?: string
  format_version?: number | null
  overview?: ContentEnvelope
  wrapped_vault_key?: AesEnvelope | null
  kms_wrapped_vault_key: RsaEnvelope | null
}

type ItemRow = {
  id: string
  vault_id: string
  version: number
  created_at: string
  updated_at: string
  content_mode?: "e2ee" | "plain"
  format_version?: number | null
  locator?: string | null
  overview?: ContentEnvelope
  details?: ContentEnvelope
  title?: string
  category?: string
  tags?: string[]
  fields?: Record<string, unknown>[]
  sections?: Record<string, unknown>[]
  urls?: { href: string; primary?: boolean }[]
  [key: string]: unknown
}

type VaultOverview = {
  name: string
  description: string
  type: string
  password_rotation_days?: number | null
}

type ItemOverview = {
  title: string
  category: string
  tags: string[]
  favorite: boolean
  state?: string
  urls: { href: string; primary?: boolean }[]
  last_edited_by?: string
  password_changed_at?: string | null
}

type ItemDetails = {
  fields: Record<string, unknown>[]
  sections: Record<string, unknown>[]
  password_history: string[]
}

class UpstreamError extends Error {
  constructor(readonly response: Response, message: string) {
    super(message)
  }
}

const encoder = new TextEncoder()

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
}

function jsonResponse(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers)
  responseHeaders.set("Content-Type", "application/json")
  return new Response(JSON.stringify(value), { status, headers: responseHeaders })
}

function standardBase64(value: Uint8Array): string {
  const encoded = encodeBase64(value).replace(/-/g, "+").replace(/_/g, "/")
  return encoded + "=".repeat((4 - encoded.length % 4) % 4)
}

function pemBytes(pem: string): Uint8Array {
  return decodeBase64(pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, ""))
}

function credentials(value: string | GoogleServiceAccountCredentials): GoogleServiceAccountCredentials {
  const parsed = typeof value === "string" ? JSON.parse(value) as GoogleServiceAccountCredentials : value
  if (!parsed.client_email || !parsed.private_key) throw new Error("Invalid GCP service account credentials")
  return parsed
}

function createGoogleUnwrapper(
  value: string | GoogleServiceAccountCredentials,
  googleFetch: typeof fetch
): VaultKeyUnwrapper {
  const serviceAccount = credentials(value)
  let accessToken: { value: string; expiresAt: number } | null = null
  let signingKey: Promise<CryptoKey> | null = null

  async function token(): Promise<string> {
    if (accessToken && Date.now() < accessToken.expiresAt - 60_000) return accessToken.value
    signingKey ??= crypto.subtle.importKey(
      "pkcs8",
      arrayBuffer(pemBytes(serviceAccount.private_key)),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    )
    const issuedAt = Math.floor(Date.now() / 1000)
    const tokenUri = serviceAccount.token_uri ?? "https://oauth2.googleapis.com/token"
    const header = encodeBase64(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })))
    const claims = encodeBase64(encoder.encode(JSON.stringify({
      iss: serviceAccount.client_email,
      scope: "https://www.googleapis.com/auth/cloud-platform",
      aud: tokenUri,
      iat: issuedAt,
      exp: issuedAt + 3600,
    })))
    const unsigned = `${header}.${claims}`
    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      await signingKey,
      arrayBuffer(encoder.encode(unsigned))
    )
    const response = await googleFetch(tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: `${unsigned}.${encodeBase64(new Uint8Array(signature))}`,
      }),
    })
    if (!response.ok) throw new Error(`GCP service account authentication failed: ${response.status}`)
    const body = await response.json() as { access_token?: string; expires_in?: number }
    if (!body.access_token) throw new Error("GCP service account authentication returned no access token")
    accessToken = {
      value: body.access_token,
      expiresAt: Date.now() + (body.expires_in ?? 3600) * 1000,
    }
    return accessToken.value
  }

  return async ({ vaultId, wrappedVaultKey, keyVersion }) => {
    const response = await googleFetch(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricDecrypt`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ciphertext: standardBase64(decodeBase64(wrappedVaultKey.ciphertext)) }),
    })
    if (!response.ok) throw new Error(`GCP KMS asymmetricDecrypt failed: ${response.status}`)
    const body = await response.json() as { plaintext?: string }
    if (!body.plaintext) throw new Error("GCP KMS returned no plaintext")
    return parseKmsPlaintext(encodeBase64(decodeBase64(body.plaintext)), vaultId)
  }
}

function namespace(pathname: string): { prefix: string; path: string } | null {
  if (pathname === "/v1" || pathname.startsWith("/v1/")) {
    return { prefix: "/v1", path: pathname.slice(3) || "/" }
  }
  const match = pathname.match(/^\/([a-z0-9][a-z0-9-]{0,62}[a-z0-9])\/v1(?:\/|$)/)
  if (!match) return null
  const prefix = `/${match[1]}/v1`
  return { prefix, path: pathname.slice(prefix.length) || "/" }
}

function itemPayload(body: Record<string, unknown>, current: Record<string, unknown>): {
  overview: ItemOverview
  details: ItemDetails
} {
  const currentFields = current.fields as Record<string, unknown>[] | undefined ?? []
  const fields = body.fields as Record<string, unknown>[] | undefined ?? currentFields
  const previousPassword = currentFields.find((field) => field.purpose === "PASSWORD")?.value
  const nextPassword = fields.find((field) => field.purpose === "PASSWORD")?.value
  const passwordField = currentFields.find((field) => field.purpose === "PASSWORD") as {
    password_details?: { history?: string[] }
  } | undefined
  const passwordHistory = (passwordField?.password_details?.history ?? []).slice(-20)
  if (typeof previousPassword === "string" && typeof nextPassword === "string" && previousPassword !== nextPassword) {
    passwordHistory.push(previousPassword)
    if (passwordHistory.length > 20) passwordHistory.shift()
  }
  return {
    overview: {
      title: String(body.title ?? current.title ?? "Untitled"),
      category: String(body.category ?? current.category ?? "LOGIN"),
      tags: body.tags as string[] | undefined ?? current.tags as string[] | undefined ?? [],
      favorite: Boolean(body.favorite ?? current.favorite ?? false),
      ...(typeof body.state === "string" || typeof current.state === "string"
        ? { state: String(body.state ?? current.state) }
        : {}),
      urls: body.urls as { href: string; primary?: boolean }[] | undefined
        ?? current.urls as { href: string; primary?: boolean }[] | undefined
        ?? [],
      ...(typeof current.last_edited_by === "string" ? { last_edited_by: current.last_edited_by } : {}),
      ...(typeof nextPassword === "string" && nextPassword !== previousPassword
        ? { password_changed_at: new Date().toISOString() }
        : typeof current.password_changed_at === "string"
          ? { password_changed_at: current.password_changed_at }
          : {}),
    },
    details: {
      fields,
      sections: body.sections as Record<string, unknown>[] | undefined
        ?? current.sections as Record<string, unknown>[] | undefined
        ?? [],
      password_history: passwordHistory,
    },
  }
}

function filterItems(items: Record<string, unknown>[], query: URLSearchParams): Record<string, unknown>[] {
  let filtered = items.filter((item) => !item.state)
  const filter = query.get("filter")
  const title = filter?.match(/title\s+eq\s+"([^"]+)"/)?.[1]
  const tag = filter?.match(/tag\s+eq\s+"([^"]+)"/)?.[1]
  if (title) filtered = filtered.filter((item) => item.title === title)
  if (tag) filtered = filtered.filter((item) => (item.tags as string[] | undefined)?.includes(tag))
  const tags = query.get("tags")?.split(",").map((entry) => entry.trim()).filter(Boolean)
  if (tags?.length) {
    filtered = filtered.filter((item) => tags.every((entry) => (item.tags as string[] | undefined)?.includes(entry)))
  }
  const categories = query.get("categories")?.split(",").map((entry) => entry.trim().toUpperCase()).filter(Boolean)
  if (categories?.length) filtered = filtered.filter((item) => categories.includes(String(item.category).toUpperCase()))
  const offset = Number(query.get("offset") ?? 0)
  const limit = query.has("limit") ? Number(query.get("limit")) : undefined
  return filtered.slice(Number.isFinite(offset) ? offset : 0, limit ? offset + limit : undefined)
}

export function createConnectClient(options: ConnectClientOptions): VaultFetcher {
  const upstream = options.fetcher ?? { fetch: (input: Request | string | URL, init?: RequestInit) => fetch(input, init) }
  const baseUrl = options.baseUrl ?? "https://vault.circles.ac"
  const googleFetch = options.googleFetch ?? fetch
  const configuredUnwrapper = options.unwrapVaultKey
    ?? (options.googleServiceAccount ? createGoogleUnwrapper(options.googleServiceAccount, googleFetch) : null)
  if (!configuredUnwrapper) throw new Error("A Vault key unwrapper is required")
  const unwrapVaultKey: VaultKeyUnwrapper = configuredUnwrapper
  const vaultKeys = new Map<string, Promise<Uint8Array>>()
  const keyVersions = new Map<string, Promise<string>>()

  async function raw(request: Request, path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers)
    const authorization = request.headers.get("Authorization")
    if (authorization) headers.set("Authorization", authorization)
    const clientId = request.headers.get("X-CVLT-Client-ID")
    if (clientId) headers.set("X-CVLT-Client-ID", clientId)
    if (init.body !== undefined && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
    return upstream.fetch(new Request(new URL(path, baseUrl), { ...init, headers }))
  }

  async function rawJson<T>(request: Request, path: string, init: RequestInit = {}): Promise<{ data: T; response: Response }> {
    const response = await raw(request, path, init)
    if (!response.ok) {
      const body = await response.text()
      throw new UpstreamError(new Response(body, { status: response.status, headers: response.headers }), body)
    }
    return { data: await response.json() as T, response }
  }

  async function keyVersion(request: Request, prefix: string): Promise<string> {
    let pending = keyVersions.get(prefix)
    if (!pending) {
      pending = rawJson<Status>(request, `${prefix}/status`).then(({ data }) => {
        if (!data.kms.key_version) throw new Error("Vault has no GCP KMS key version")
        return data.kms.key_version
      })
      keyVersions.set(prefix, pending)
    }
    return pending
  }

  async function vaultKey(request: Request, prefix: string, row: VaultRow): Promise<Uint8Array> {
    let pending = vaultKeys.get(row.id)
    if (!pending) {
      if (!row.kms_wrapped_vault_key) throw new Error(`Vault ${row.id} has no KMS-wrapped key`)
      pending = unwrapVaultKey({
        vaultId: row.id,
        wrappedVaultKey: row.kms_wrapped_vault_key,
        keyVersion: await keyVersion(request, prefix),
      })
      vaultKeys.set(row.id, pending)
    }
    return pending
  }

  async function vaultValue(request: Request, prefix: string, row: VaultRow): Promise<Record<string, unknown>> {
    if (row.content_mode === "plain") return { ...row }
    if (!row.overview) throw new Error(`Vault ${row.id} has no encrypted overview`)
    const overview = await decryptJson<VaultOverview>(
      row.overview,
      await vaultKey(request, prefix, row),
      `cvlt:v1:vault:${row.id}:overview`
    )
    return {
      id: row.id,
      name: overview.name,
      content_version: row.content_version,
      attribute_version: row.attribute_version,
      type: overview.type,
      items: row.items,
      created_at: row.created_at,
      updated_at: row.updated_at,
      ...(overview.description ? { description: overview.description } : {}),
      ...(overview.password_rotation_days != null ? { password_rotation_days: overview.password_rotation_days } : {}),
      ...(row.integration_coordinate ? { integration_coordinate: row.integration_coordinate } : {}),
    }
  }

  async function itemValue(
    request: Request,
    prefix: string,
    row: ItemRow,
    vault: VaultRow
  ): Promise<Record<string, unknown>> {
    if (row.content_mode === "plain") {
      const vaultOverview = await vaultValue(request, prefix, vault)
      return { ...row, vault: { id: row.vault_id, name: vaultOverview.name } }
    }
    if (!row.overview || !row.details) throw new Error(`Item ${row.id} has incomplete encrypted data`)
    const key = await vaultKey(request, prefix, vault)
    const overview = await decryptJson<ItemOverview>(
      row.overview,
      key,
      `cvlt:v1:vault:${row.vault_id}:item:${row.id}:overview`
    )
    const details = await decryptJson<ItemDetails>(
      row.details,
      key,
      `cvlt:v1:vault:${row.vault_id}:item:${row.id}:details`
    )
    const vaultOverview = await vaultValue(request, prefix, vault)
    const fields = details.fields.map((field) => field.purpose !== "PASSWORD" || details.password_history.length === 0
      ? field
      : {
          ...field,
          password_details: {
            ...(field.password_details as Record<string, unknown> | undefined),
            history: details.password_history,
          },
        })
    return {
      id: row.id,
      title: overview.title,
      version: row.version,
      vault: { id: row.vault_id, name: vaultOverview.name },
      category: overview.category,
      fields,
      sections: details.sections,
      urls: overview.urls,
      created_at: row.created_at,
      updated_at: row.updated_at,
      ...(overview.tags.length ? { tags: overview.tags } : {}),
      ...(overview.favorite ? { favorite: true } : {}),
      ...(overview.state ? { state: overview.state } : {}),
      ...(overview.last_edited_by ? { last_edited_by: overview.last_edited_by } : {}),
      ...(overview.password_changed_at ? { password_changed_at: overview.password_changed_at } : {}),
    }
  }

  return {
    async fetch(input, init) {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init)
      const url = new URL(request.url)
      const target = namespace(url.pathname)
      if (!target || !target.path.startsWith("/vaults")) return upstream.fetch(request)
      const parts = target.path.split("/").filter(Boolean)
      try {
        if (parts.length === 1 && request.method === "GET") {
          const { data } = await rawJson<VaultRow[]>(request, `${target.prefix}/vaults`)
          const vaults = await Promise.all(data.map((row) => vaultValue(request, target.prefix, row)))
          return jsonResponse(filterVaults(vaults, url.searchParams))
        }

        const vaultId = parts[1]
        if (!vaultId) return upstream.fetch(request)
        const { data: vault } = await rawJson<VaultRow>(request, `${target.prefix}/vaults/${encodeURIComponent(vaultId)}`)
        if (parts.length === 2 && request.method === "GET") {
          return jsonResponse(await vaultValue(request, target.prefix, vault))
        }
        if (parts.length === 2 && request.method === "PUT") {
          if (vault.content_mode === "plain") return upstream.fetch(request)
          const current = await vaultValue(request, target.prefix, vault)
          const body = await request.json() as Record<string, unknown>
          const overview: VaultOverview = {
            name: String(body.name ?? current.name),
            description: String(body.description ?? current.description ?? ""),
            type: String(current.type ?? "USER_CREATED"),
            ...(body.password_rotation_days !== undefined
              ? { password_rotation_days: body.password_rotation_days as number | null }
              : current.password_rotation_days !== undefined
                ? { password_rotation_days: current.password_rotation_days as number }
                : {}),
          }
          const { data: updated } = await rawJson<VaultRow>(request, `${target.prefix}/vaults/${encodeURIComponent(vaultId)}`, {
            method: "PUT",
            body: JSON.stringify({
              overview: await encryptJson(
                overview,
                await vaultKey(request, target.prefix, vault),
                `cvlt:v1:vault:${vaultId}:overview`
              ),
            }),
          })
          return jsonResponse(await vaultValue(request, target.prefix, updated))
        }
        if (parts[2] !== "items") return upstream.fetch(request)
        if (parts.length === 3 && request.method === "GET") {
          const { data } = await rawJson<ItemRow[]>(request, `${target.prefix}/vaults/${encodeURIComponent(vaultId)}/items`)
          const items = await Promise.all(data.map((row) => itemValue(request, target.prefix, row, vault)))
          return jsonResponse(filterItems(items, url.searchParams))
        }

        if (parts[3] === "resolve" && parts.length === 4 && request.method === "POST") {
          const body = await request.json() as Record<string, unknown>
          if (typeof body.title !== "string" || body.title.length === 0) {
            return jsonResponse({ status: 400, message: "Item title is required" }, 400)
          }
          const { data } = await rawJson<ItemRow[]>(request, `${target.prefix}/vaults/${encodeURIComponent(vaultId)}/items`)
          for (const row of data) {
            const item = await itemValue(request, target.prefix, row, vault)
            if (item.title === body.title) return jsonResponse(item)
          }
          return jsonResponse({ status: 404, message: "Item not found" }, 404)
        }

        const itemId = parts[3]
        if (!itemId || parts.length !== 4) return upstream.fetch(request)
        const itemPath = `${target.prefix}/vaults/${encodeURIComponent(vaultId)}/items/${encodeURIComponent(itemId)}`
        const { data: row } = await rawJson<ItemRow>(request, itemPath)
        if (request.method === "GET") {
          return jsonResponse(await itemValue(request, target.prefix, row, vault), 200, { ETag: `"${row.version}"` })
        }
        if (request.method === "PUT") {
          if (row.content_mode === "plain") return upstream.fetch(request)
          const ifMatch = request.headers.get("If-Match")?.replace(/^W\//, "").replaceAll('"', "")
          const expectedVersion = ifMatch === undefined ? row.version : Number(ifMatch)
          if (!Number.isSafeInteger(expectedVersion) || expectedVersion !== row.version) {
            return jsonResponse({ status: 412, message: "Item version changed" }, 412)
          }
          const current = await itemValue(request, target.prefix, row, vault)
          const body = await request.json() as Record<string, unknown>
          const payload = itemPayload(body, current)
          const key = await vaultKey(request, target.prefix, vault)
          const { data: updated } = await rawJson<ItemRow>(request, itemPath, {
            method: "PUT",
            body: JSON.stringify({
              version: expectedVersion,
              locator: await itemLocator(key, payload.overview.title),
              overview: await encryptJson(
                payload.overview,
                key,
                `cvlt:v1:vault:${vaultId}:item:${itemId}:overview`
              ),
              details: await encryptJson(
                payload.details,
                key,
                `cvlt:v1:vault:${vaultId}:item:${itemId}:details`
              ),
            }),
          })
          return jsonResponse(
            await itemValue(request, target.prefix, updated, vault),
            200,
            { ETag: `"${updated.version}"` }
          )
        }
        return upstream.fetch(request)
      } catch (error) {
        if (error instanceof UpstreamError) return error.response
        throw error
      }
    },
  }
}
