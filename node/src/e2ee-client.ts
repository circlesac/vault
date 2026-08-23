import { loadDeviceKey, saveDeviceKey } from "./key-store"
import { parseVaultCoordinate } from "./refs"
import {
  createRecoveryEnvelope,
  decryptContent,
  decryptJson,
  decryptManagementChallenge,
  encodeBase64,
  encryptContent,
  encryptJson,
  EMPTY_BODY_SHA256,
  generateDeviceKey,
  generateOpaqueId,
  itemLocator,
  openRecoveryEnvelope,
  parseEncryptedBytes,
  parseKmsPlaintext,
  publicKeyFingerprint,
  randomKey,
  serializeEncryptedBytes,
  sha256Hex,
  unwrapAccountKeyForDevice,
  unwrapKey,
  wrapAccountKeyForDevice,
  wrapKey,
  wrapVaultKeyForKms,
  type AesEnvelope,
  type ContentEnvelope,
  type DeviceKey,
  type RecoveryEnvelope,
  type RsaEnvelope,
} from "./e2ee-crypto"
import {
  assertPublicJwk,
  decodeEnrollmentRequest,
  encodeEnrollmentRequest,
  formatFingerprint,
  normalizeClientName,
  normalizeVaultOrigin,
  type EnrollmentRequest,
} from "./client-enrollment"
import { filterVaults } from "./connect-filters.js"

export type VaultConfig = {
  baseUrl: string
  token: string
  org: string | null
  /** False for an opaque API-key credential, which has no installation key. */
  installationIdentity?: boolean
}
export type RequestOptions = { method?: string; body?: unknown }
export type OidcTokenFetcher = (audience: string) => Promise<string | null>

type Status = {
  account: string
  initialized: boolean
  format_version: number | null
  client: {
    id: string
    public_key: JsonWebKey
    wrapped_account_key: RsaEnvelope
    platform: string | null
    created_at: string
  } | null
  kms: {
    public_key_pem: string | null
    wif_audience: string | null
    key_version: string | null
  }
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
  coordinate: { provider: string; owner: string; repository: string | null } | null
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

type FileRow = {
  id: string
  item_id: string
  vault_id: string
  created_at: string
  format_version: number
  metadata: ContentEnvelope
  ciphertext_size: number
  content_path: string
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

type FileMetadata = { name: string; content_type: string; size: number }

type CryptoContext = {
  status: Status
  device: DeviceKey | null
  accountKey: Uint8Array | null
}

export class VaultApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

const NOT_REGISTERED_MESSAGE =
  "This installation is not registered. Run cvlt client request and approve it from a registered installation, or run cvlt recover after a fresh crcl login"

const NOT_INITIALIZED_MESSAGE =
  "Account encryption is not initialized. Run a first write from the installation that should own this account to bootstrap it; enrollment only adds installations to an initialized account"

const cryptoContexts = new Map<string, CryptoContext>()
const deviceKeys = new Map<string, Promise<DeviceKey | null>>()
const initializedAccountDevices = new Map<string, Promise<DeviceKey | null>>()
const pendingCryptoContexts = new Map<string, Promise<CryptoContext>>()
const pendingBootstraps = new Map<string, Promise<CryptoContext>>()
const vaultKeys = new Map<string, Uint8Array>()
const pendingVaultKeys = new Map<string, Promise<Uint8Array>>()
const vaultRowLists = new Map<string, Promise<VaultRow[]>>()
const vaultRowsById = new Map<string, VaultRow>()
const itemRowLists = new Map<string, Promise<ItemRow[]>>()
const itemRowsById = new Map<string, ItemRow>()
const encoder = new TextEncoder()

export function resetE2eeCaches() {
  cryptoContexts.clear()
  deviceKeys.clear()
  initializedAccountDevices.clear()
  pendingCryptoContexts.clear()
  pendingBootstraps.clear()
  vaultKeys.clear()
  pendingVaultKeys.clear()
  vaultRowLists.clear()
  vaultRowsById.clear()
  itemRowLists.clear()
  itemRowsById.clear()
}

async function originDeviceKey(origin: string): Promise<DeviceKey | null> {
  let pending = deviceKeys.get(origin)
  if (!pending) {
    pending = loadDeviceKey(origin)
    deviceKeys.set(origin, pending)
  }
  try {
    const device = await pending
    if (device === null && deviceKeys.get(origin) === pending) deviceKeys.delete(origin)
    return device
  } catch (error) {
    if (deviceKeys.get(origin) === pending) deviceKeys.delete(origin)
    throw error
  }
}

function rememberDeviceKey(origin: string, device: DeviceKey): void {
  deviceKeys.set(origin, Promise.resolve(device))
}

function configCacheKey(config: VaultConfig): string {
  return `${config.baseUrl}\0${config.token}`
}

/** Omit the origin key only while the selected account is not initialized.
 * Once initialized, even an unregistered or revoked installation keeps sending
 * its ID and receives the intended 403 instead of falling through the legacy
 * no-header compatibility path. Null results are not retained because another
 * process may initialize the account while this process remains alive. */
async function initializedAccountDevice(config: VaultConfig): Promise<DeviceKey | null> {
  const cacheKey = configCacheKey(config)
  let pending = initializedAccountDevices.get(cacheKey)
  if (!pending) {
    pending = (async () => {
      const device = await originDeviceKey(new URL(config.baseUrl).origin)
      if (!device) return null
      const status = await readStatus(config, device)
      return status.initialized ? device : null
    })()
    initializedAccountDevices.set(cacheKey, pending)
  }
  try {
    const device = await pending
    if (device === null && initializedAccountDevices.get(cacheKey) === pending) {
      initializedAccountDevices.delete(cacheKey)
    }
    return device
  } catch (error) {
    if (initializedAccountDevices.get(cacheKey) === pending) initializedAccountDevices.delete(cacheKey)
    throw error
  }
}

function rememberInitializedAccountDevice(config: VaultConfig, device: DeviceKey): void {
  initializedAccountDevices.set(configCacheKey(config), Promise.resolve(device))
}

function vaultRowCacheKey(config: VaultConfig, vaultId: string): string {
  return `${configCacheKey(config)}\0${vaultId}`
}

function itemRowCacheKey(config: VaultConfig, vaultId: string, itemId: string): string {
  return `${vaultRowCacheKey(config, vaultId)}\0${itemId}`
}

function rememberVaultRow(config: VaultConfig, row: VaultRow): VaultRow {
  vaultRowsById.set(vaultRowCacheKey(config, row.id), row)
  return row
}

function rememberItemRow(config: VaultConfig, row: ItemRow): ItemRow {
  itemRowsById.set(itemRowCacheKey(config, row.vault_id, row.id), row)
  return row
}

function invalidateVaultList(config: VaultConfig): void {
  vaultRowLists.delete(configCacheKey(config))
}

function invalidateVaultRow(config: VaultConfig, vaultId: string): void {
  vaultRowsById.delete(vaultRowCacheKey(config, vaultId))
  invalidateVaultList(config)
}

function invalidateItemList(config: VaultConfig, vaultId: string): void {
  itemRowLists.delete(vaultRowCacheKey(config, vaultId))
}

function removeVaultRow(config: VaultConfig, vaultId: string): void {
  invalidateVaultRow(config, vaultId)
  vaultKeys.delete(vaultRowCacheKey(config, vaultId))
  pendingVaultKeys.delete(vaultRowCacheKey(config, vaultId))
  invalidateItemList(config, vaultId)
  for (const key of itemRowsById.keys()) {
    if (key.startsWith(`${vaultRowCacheKey(config, vaultId)}\0`)) itemRowsById.delete(key)
  }
}

function removeItemRow(config: VaultConfig, vaultId: string, itemId: string): void {
  itemRowsById.delete(itemRowCacheKey(config, vaultId, itemId))
  invalidateItemList(config, vaultId)
}

function authHeaders(config: VaultConfig, device?: DeviceKey | null): Record<string, string> {
  const headers: Record<string, string> = { Authorization: `Bearer ${config.token}` }
  if (device) headers["X-CVLT-Client-ID"] = device.clientId
  return headers
}

/** Include the local installation identity on ordinary signed-in-user data
 * requests. Manual OP_CONNECT_TOKEN credentials may be API keys, whose data
 * path deliberately has no device key; opening the local key store first would
 * break existing headless integrations before they reach the server. */
async function dataAuthHeaders(config: VaultConfig): Promise<Record<string, string>> {
  if (isOidc() || config.installationIdentity === false) return authHeaders(config)
  const context = cryptoContexts.get(configCacheKey(config))
  const cached = context?.device && context.status.client?.id === context.device.clientId
    ? context.device
    : null
  const device = cached ?? await initializedAccountDevice(config)
  return authHeaders(config, device)
}

/** The data routes the service gates on the installation identity. A request
 * path may carry a query string — `/v1/coordinates?provider=…` is how every
 * `vlt://` read starts — so match the pathname alone, never the whole path. */
function needsInstallationHeader(path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0]!
  return pathname === "/v1/vaults"
    || pathname.startsWith("/v1/vaults/")
    || pathname === "/v1/coordinates"
    || pathname === "/v1/coordinates/read"
}

async function errorMessage(response: Response): Promise<string> {
  const text = await response.text()
  try {
    return (JSON.parse(text) as { message?: string }).message || text
  } catch {
    return text
  }
}

async function jsonRequest<T>(
  config: VaultConfig,
  path: string,
  options: RequestOptions = {},
  headers: Record<string, string> = {}
): Promise<T> {
  const requestHeaders = {
    ...(needsInstallationHeader(path) ? await dataAuthHeaders(config) : authHeaders(config)),
    ...headers,
  }
  if (options.body !== undefined) requestHeaders["Content-Type"] = "application/json"
  const response = await fetch(`${config.baseUrl}${path}`, {
    method: options.method || "GET",
    headers: requestHeaders,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function isOidc(): boolean {
  return !process.env.OP_CONNECT_TOKEN
    && !!(process.env.ACTIONS_ID_TOKEN_REQUEST_URL && process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
}

async function readStatus(config: VaultConfig, device: DeviceKey | null): Promise<Status> {
  return jsonRequest<Status>(config, "/v1/status", {}, device ? { "X-CVLT-Client-ID": device.clientId } : {})
}

async function bootstrap(config: VaultConfig, device: DeviceKey | null): Promise<CryptoContext> {
  if (isOidc()) throw new Error("GitHub Actions cannot initialize account encryption")
  if (config.installationIdentity === false) {
    throw new Error("API keys cannot initialize account encryption")
  }
  const origin = new URL(config.baseUrl).origin
  const installation = device ?? await generateDeviceKey()
  if (!device) {
    await saveDeviceKey(origin, installation)
    rememberDeviceKey(origin, installation)
  }
  const status = await readStatus(config, installation)
  if (status.initialized) {
    if (!status.client) {
      throw new Error(NOT_REGISTERED_MESSAGE)
    }
    const accountKey = await unwrapAccountKeyForDevice(
      status.client.wrapped_account_key,
      installation.privateKey,
      status.account
    )
    const context = { status, device: installation, accountKey }
    cryptoContexts.set(configCacheKey(config), context)
    return context
  }
  const accountKey = randomKey()
  const recovery = await createRecoveryEnvelope(accountKey, status.account)
  await jsonRequest(config, "/v1/bootstrap", {
    method: "POST",
    body: {
      client: {
        id: installation.clientId,
        public_key: installation.publicKey,
        wrapped_account_key: await wrapAccountKeyForDevice(accountKey, installation.publicKey, status.account),
        platform: process.platform,
      },
      recovery: recovery.envelope,
    },
  })
  process.stderr.write("\nCircles Vault recovery code (store it outside Vault):\n")
  process.stderr.write(`${recovery.code}\n\n`)
  const initialized = await readStatus(config, installation)
  const context = { status: initialized, device: installation, accountKey }
  cryptoContexts.set(configCacheKey(config), context)
  return context
}

async function cryptoContext(config: VaultConfig, allowBootstrap: boolean): Promise<CryptoContext> {
  const cacheKey = configCacheKey(config)
  const cached = cryptoContexts.get(cacheKey)
  if (cached) return cached
  const pending = pendingCryptoContexts.get(cacheKey)
  if (pending) {
    const context = await pending
    return !context.status.initialized && allowBootstrap
      ? bootstrapContext(config, context.device)
      : context
  }
  const loading = (async () => {
    const usesDeviceIdentity = !isOidc() && config.installationIdentity !== false
    const device = usesDeviceIdentity ? await originDeviceKey(new URL(config.baseUrl).origin) : null
    const status = await readStatus(config, device)
    if (!status.initialized) {
      if (!allowBootstrap) return { status, device, accountKey: null }
      return bootstrapContext(config, device)
    }
    if (!usesDeviceIdentity) {
      const context = { status, device: null, accountKey: null }
      cryptoContexts.set(cacheKey, context)
      return context
    }
    if (!device || !status.client) {
      throw new Error(NOT_REGISTERED_MESSAGE)
    }
    rememberInitializedAccountDevice(config, device)
    const accountKey = await unwrapAccountKeyForDevice(
      status.client.wrapped_account_key,
      device.privateKey,
      status.account
    )
    const context = { status, device, accountKey }
    cryptoContexts.set(cacheKey, context)
    return context
  })()
  pendingCryptoContexts.set(cacheKey, loading)
  try {
    return await loading
  } finally {
    pendingCryptoContexts.delete(cacheKey)
  }
}

async function bootstrapContext(config: VaultConfig, device: DeviceKey | null): Promise<CryptoContext> {
  const cacheKey = configCacheKey(config)
  const cached = cryptoContexts.get(cacheKey)
  if (cached) return cached
  const pending = pendingBootstraps.get(cacheKey)
  if (pending) return pending
  const loading = bootstrap(config, device)
  pendingBootstraps.set(cacheKey, loading)
  try {
    return await loading
  } finally {
    pendingBootstraps.delete(cacheKey)
  }
}

async function kmsVaultKey(
  context: CryptoContext,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Uint8Array> {
  const { wif_audience: audience, key_version: keyVersion } = context.status.kms
  if (!row.kms_wrapped_vault_key || !audience || !keyVersion) {
    throw new Error(`Vault ${row.id} has no GitHub OIDC KMS envelope`)
  }
  const subjectToken = await fetchOidcToken(audience)
  if (!subjectToken) throw new Error("Unable to mint a GitHub OIDC token for GCP")
  const sts = await fetch("https://sts.googleapis.com/v1/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
      audience,
      requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
      scope: "https://www.googleapis.com/auth/cloud-platform",
      subjectToken,
      subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    }),
  })
  if (!sts.ok) throw new Error(`GCP STS token exchange failed: ${sts.status}`)
  const accessToken = ((await sts.json()) as { access_token?: string }).access_token
  if (!accessToken) throw new Error("GCP STS returned no access token")
  const decrypted = await fetch(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricDecrypt`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ ciphertext: Buffer.from(row.kms_wrapped_vault_key.ciphertext, "base64url").toString("base64") }),
  })
  if (!decrypted.ok) throw new Error(`GCP KMS asymmetricDecrypt failed: ${decrypted.status}`)
  const plaintext = ((await decrypted.json()) as { plaintext?: string }).plaintext
  if (!plaintext) throw new Error("GCP KMS returned no plaintext")
  return parseKmsPlaintext(Buffer.from(plaintext, "base64").toString("base64url"), row.id)
}

async function vaultKey(
  config: VaultConfig,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Uint8Array> {
  const cacheKey = vaultRowCacheKey(config, row.id)
  const cached = vaultKeys.get(cacheKey)
  if (cached) return cached
  const pending = pendingVaultKeys.get(cacheKey)
  if (pending) return pending
  const loading = (async () => {
    const context = await cryptoContext(config, false)
    let key: Uint8Array
    if (isOidc()) {
      key = await kmsVaultKey(context, row, fetchOidcToken)
    } else {
      if (!context.accountKey || !row.wrapped_vault_key) throw new Error(`Vault ${row.id} has no account key envelope`)
      key = await unwrapKey(
        row.wrapped_vault_key,
        context.accountKey,
        `cvlt:v1:account:${context.status.account}:vault:${row.id}`
      )
    }
    vaultKeys.set(cacheKey, key)
    return key
  })()
  pendingVaultKeys.set(cacheKey, loading)
  try {
    return await loading
  } finally {
    pendingVaultKeys.delete(cacheKey)
  }
}

async function encryptedVault(
  config: VaultConfig,
  row: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (row.content_mode === "plain") return { ...row }
  if (!row.overview) throw new Error(`Vault ${row.id} has no encrypted overview`)
  const overview = await decryptJson<VaultOverview>(
    row.overview,
    await vaultKey(config, row, fetchOidcToken),
    `cvlt:v1:vault:${row.id}:overview`
  )
  const result: Record<string, unknown> = {
    id: row.id,
    name: overview.name,
    content_version: row.content_version,
    attribute_version: row.attribute_version,
    type: overview.type,
    items: row.items,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }
  if (overview.description) result.description = overview.description
  if (overview.password_rotation_days != null) result.password_rotation_days = overview.password_rotation_days
  return result
}

async function vaultRows(config: VaultConfig): Promise<VaultRow[]> {
  const cacheKey = configCacheKey(config)
  const cached = vaultRowLists.get(cacheKey)
  if (cached) return cached
  const loading = jsonRequest<VaultRow[]>(config, "/v1/vaults")
    .then((rows) => rows.map((row) => rememberVaultRow(config, row)))
  vaultRowLists.set(cacheKey, loading)
  try {
    return await loading
  } catch (error) {
    if (vaultRowLists.get(cacheKey) === loading) vaultRowLists.delete(cacheKey)
    throw error
  }
}

async function findVaultRow(config: VaultConfig, vaultId: string): Promise<VaultRow> {
  const cacheKey = vaultRowCacheKey(config, vaultId)
  const cached = vaultRowsById.get(cacheKey)
  if (cached) return cached
  const pendingList = vaultRowLists.get(configCacheKey(config))
  if (pendingList) {
    await pendingList
    const listed = vaultRowsById.get(cacheKey)
    if (listed) return listed
  }
  return rememberVaultRow(config, await jsonRequest<VaultRow>(config, `/v1/vaults/${vaultId}`))
}

async function itemRows(config: VaultConfig, vaultId: string): Promise<ItemRow[]> {
  const cacheKey = vaultRowCacheKey(config, vaultId)
  const cached = itemRowLists.get(cacheKey)
  if (cached) return cached
  const loading = jsonRequest<ItemRow[]>(config, `/v1/vaults/${vaultId}/items`)
    .then((rows) => rows.map((row) => rememberItemRow(config, row)))
  itemRowLists.set(cacheKey, loading)
  try {
    return await loading
  } catch (error) {
    if (itemRowLists.get(cacheKey) === loading) itemRowLists.delete(cacheKey)
    throw error
  }
}

async function findItemRow(config: VaultConfig, vaultId: string, itemId: string): Promise<ItemRow> {
  const cacheKey = itemRowCacheKey(config, vaultId, itemId)
  const cached = itemRowsById.get(cacheKey)
  if (cached && (cached.content_mode !== "plain" || cached.fields !== undefined)) return cached
  const pendingList = itemRowLists.get(vaultRowCacheKey(config, vaultId))
  if (pendingList) {
    await pendingList
    const listed = itemRowsById.get(cacheKey)
    if (listed && (listed.content_mode !== "plain" || listed.fields !== undefined)) return listed
  }
  return rememberItemRow(
    config,
    await jsonRequest<ItemRow>(config, `/v1/vaults/${vaultId}/items/${itemId}`)
  )
}

async function encryptedItem(
  config: VaultConfig,
  row: ItemRow,
  vault: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (row.content_mode === "plain") return { ...row, vault: { id: row.vault_id } }
  if (!row.overview || !row.details) throw new Error(`Item ${row.id} has incomplete encrypted data`)
  const key = await vaultKey(config, vault, fetchOidcToken)
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
  const fields = details.fields.map((field) => {
    if (field.purpose !== "PASSWORD" || details.password_history.length === 0) return field
    return {
      ...field,
      password_details: {
        ...(field.password_details as Record<string, unknown> | undefined),
        history: details.password_history,
      },
    }
  })
  const result: Record<string, unknown> = {
    id: row.id,
    title: overview.title,
    version: row.version,
    vault: { id: row.vault_id },
    category: overview.category,
    fields,
    sections: details.sections,
    urls: overview.urls,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }
  if (overview.tags.length) result.tags = overview.tags
  if (overview.favorite) result.favorite = true
  if (overview.state) result.state = overview.state
  if (overview.last_edited_by) result.last_edited_by = overview.last_edited_by
  if (overview.password_changed_at) result.password_changed_at = overview.password_changed_at
  return result
}

function itemPayload(body: Record<string, unknown>, current?: Record<string, unknown>): {
  overview: ItemOverview
  details: ItemDetails
} {
  const currentFields = (current?.fields as Record<string, unknown>[] | undefined) ?? []
  const fields = (body.fields as Record<string, unknown>[] | undefined) ?? currentFields
  const previousPassword = currentFields.find((field) => field.purpose === "PASSWORD")?.value
  const nextPassword = fields.find((field) => field.purpose === "PASSWORD")?.value
  const passwordField = currentFields.find((field) => field.purpose === "PASSWORD") as {
    password_details?: { history?: string[] }
  } | undefined
  const currentHistory = (passwordField?.password_details?.history ?? []).slice(-20)
  if (typeof previousPassword === "string" && typeof nextPassword === "string" && previousPassword !== nextPassword) {
    currentHistory.push(previousPassword)
    if (currentHistory.length > 20) currentHistory.shift()
  }
  return {
    overview: {
      title: String(body.title ?? current?.title ?? "Untitled"),
      category: String(body.category ?? current?.category ?? "LOGIN"),
      tags: (body.tags as string[] | undefined) ?? (current?.tags as string[] | undefined) ?? [],
      favorite: Boolean(body.favorite ?? current?.favorite ?? false),
      ...(typeof body.state === "string" || typeof current?.state === "string"
        ? { state: String(body.state ?? current?.state) }
        : {}),
      urls: (body.urls as { href: string; primary?: boolean }[] | undefined)
        ?? (current?.urls as { href: string; primary?: boolean }[] | undefined)
        ?? [],
      ...(typeof current?.last_edited_by === "string" ? { last_edited_by: current.last_edited_by } : {}),
      ...(typeof nextPassword === "string" && nextPassword !== previousPassword
        ? { password_changed_at: new Date().toISOString() }
        : typeof current?.password_changed_at === "string"
          ? { password_changed_at: current.password_changed_at }
        : {}),
    },
    details: {
      fields,
      sections: (body.sections as Record<string, unknown>[] | undefined)
        ?? (current?.sections as Record<string, unknown>[] | undefined)
        ?? [],
      password_history: currentHistory,
    },
  }
}

async function createItem(
  config: VaultConfig,
  vault: VaultRow,
  body: Record<string, unknown>,
  fetchOidcToken: OidcTokenFetcher,
  id = generateOpaqueId()
): Promise<Record<string, unknown>> {
  if (vault.content_mode === "plain") {
    return jsonRequest<Record<string, unknown>>(config, `/v1/vaults/${vault.id}/items`, {
      method: "POST",
      body: { ...body, id, content_mode: "plain" },
    })
  }
  const key = await vaultKey(config, vault, fetchOidcToken)
  const payload = itemPayload(body)
  const row = await jsonRequest<ItemRow>(config, `/v1/vaults/${vault.id}/items`, {
    method: "POST",
    body: {
      id,
      locator: await itemLocator(key, payload.overview.title),
      overview: await encryptJson(payload.overview, key, `cvlt:v1:vault:${vault.id}:item:${id}:overview`),
      details: await encryptJson(payload.details, key, `cvlt:v1:vault:${vault.id}:item:${id}:details`),
    },
  })
  rememberItemRow(config, row)
  invalidateItemList(config, vault.id)
  invalidateVaultRow(config, vault.id)
  return encryptedItem(config, row, vault, fetchOidcToken)
}

async function updateItem(
  config: VaultConfig,
  vault: VaultRow,
  row: ItemRow,
  body: Record<string, unknown>,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (row.content_mode === "plain") {
    return jsonRequest<Record<string, unknown>>(config, `/v1/vaults/${vault.id}/items/${row.id}`, {
      method: "PUT",
      body: { ...body, version: row.version },
    })
  }
  const current = await encryptedItem(config, row, vault, fetchOidcToken)
  const key = await vaultKey(config, vault, fetchOidcToken)
  const payload = itemPayload(body, current)
  const updated = await jsonRequest<ItemRow>(config, `/v1/vaults/${vault.id}/items/${row.id}`, {
    method: "PUT",
    body: {
      version: row.version,
      locator: await itemLocator(key, payload.overview.title),
      overview: await encryptJson(payload.overview, key, `cvlt:v1:vault:${vault.id}:item:${row.id}:overview`),
      details: await encryptJson(payload.details, key, `cvlt:v1:vault:${vault.id}:item:${row.id}:details`),
    },
  })
  rememberItemRow(config, updated)
  invalidateItemList(config, vault.id)
  invalidateVaultRow(config, vault.id)
  return encryptedItem(config, updated, vault, fetchOidcToken)
}

function filterItems(items: Record<string, unknown>[], query: URLSearchParams): Record<string, unknown>[] {
  let filtered = items.filter((item) => !item.state)
  const filter = query.get("filter")
  const title = filter?.match(/title\s+eq\s+"([^"]+)"/)?.[1]
  const tag = filter?.match(/tag\s+eq\s+"([^"]+)"/)?.[1]
  if (title) filtered = filtered.filter((item) => item.title === title)
  if (tag) filtered = filtered.filter((item) => (item.tags as string[] | undefined)?.includes(tag))
  const tags = query.get("tags")?.split(",").map((value) => value.trim()).filter(Boolean)
  if (tags?.length) filtered = filtered.filter((item) => tags.every((value) => (item.tags as string[] | undefined)?.includes(value)))
  const categories = query.get("categories")?.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean)
  if (categories?.length) filtered = filtered.filter((item) => categories.includes(String(item.category).toUpperCase()))
  const offset = Number(query.get("offset") ?? 0)
  const limit = query.has("limit") ? Number(query.get("limit")) : undefined
  return filtered.slice(Number.isFinite(offset) ? offset : 0, limit ? offset + limit : undefined)
}

async function fileRows(config: VaultConfig, vaultId: string, itemId: string): Promise<FileRow[]> {
  return jsonRequest<FileRow[]>(config, `/v1/vaults/${vaultId}/items/${itemId}/files`)
}

async function encryptedFileInfo(
  config: VaultConfig,
  row: FileRow,
  vault: VaultRow,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (!row.metadata) throw new Error(`File ${row.id} has no encrypted metadata`)
  const metadata = await decryptJson<FileMetadata>(
    row.metadata,
    await vaultKey(config, vault, fetchOidcToken),
    `cvlt:v1:vault:${row.vault_id}:item:${row.item_id}:file:${row.id}:metadata`
  )
  return {
    id: row.id,
    name: metadata.name,
    size: metadata.size,
    content_type: metadata.content_type,
    content_path: row.content_path,
  }
}

export async function uploadEncryptedFile(
  config: VaultConfig,
  vaultId: string,
  itemId: string,
  name: string,
  contentType: string,
  content: Uint8Array,
  fetchOidcToken: OidcTokenFetcher
): Promise<Record<string, unknown>> {
  if (content.byteLength > 10 * 1024 * 1024) throw new Error("File exceeds 10MB limit")
  const vault = await findVaultRow(config, vaultId)
  const key = await vaultKey(config, vault, fetchOidcToken)
  const fileId = generateOpaqueId()
  const metadata = await encryptJson(
    { name, content_type: contentType || "application/octet-stream", size: content.byteLength },
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:metadata`
  )
  const encrypted = serializeEncryptedBytes(await encryptContent(
    content,
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:content`
  ))
  const response = await fetch(`${config.baseUrl}/v1/vaults/${vaultId}/items/${itemId}/files`, {
    method: "POST",
    headers: {
      ...await dataAuthHeaders(config),
      "Content-Type": "application/octet-stream",
      "X-CVLT-File-ID": fileId,
      "X-CVLT-Metadata": Buffer.from(JSON.stringify(metadata)).toString("base64url"),
    },
    body: encrypted,
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  return encryptedFileInfo(config, await response.json() as FileRow, vault, fetchOidcToken)
}

export async function downloadEncryptedFile(
  config: VaultConfig,
  vaultId: string,
  itemId: string,
  fileId: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ info: Record<string, unknown>; content: Uint8Array }> {
  const vault = await findVaultRow(config, vaultId)
  const row = (await fileRows(config, vaultId, itemId)).find((file) => file.id === fileId)
  if (!row) throw new Error("File not found")
  const response = await fetch(`${config.baseUrl}/v1/vaults/${vaultId}/items/${itemId}/files/${fileId}/content`, {
    headers: await dataAuthHeaders(config),
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  const key = await vaultKey(config, vault, fetchOidcToken)
  const content = await decryptContent(
    parseEncryptedBytes(new Uint8Array(await response.arrayBuffer())),
    key,
    `cvlt:v1:vault:${vaultId}:item:${itemId}:file:${fileId}:content`
  )
  return { info: await encryptedFileInfo(config, row, vault, fetchOidcToken), content }
}

async function createVault(
  config: VaultConfig,
  body: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const context = await cryptoContext(config, true)
  if (!context.accountKey) throw new Error("A user account key is required to create a vault")
  const id = generateOpaqueId()
  const key = randomKey()
  const overview: VaultOverview = {
    name: String(body.name ?? ""),
    description: String(body.description ?? ""),
    type: "USER_CREATED",
    ...(body.password_rotation_days !== undefined
      ? { password_rotation_days: body.password_rotation_days as number | null }
      : {}),
  }
  const coordinate = parseVaultCoordinate(overview.name)
  const kmsWrapped = context.status.kms.public_key_pem
    ? await wrapVaultKeyForKms(key, id, context.status.kms.public_key_pem)
    : null
  const row = await jsonRequest<VaultRow>(config, "/v1/vaults", {
    method: "POST",
    body: {
      id,
      overview: await encryptJson(overview, key, `cvlt:v1:vault:${id}:overview`),
      wrapped_vault_key: await wrapKey(
        key,
        context.accountKey,
        `cvlt:v1:account:${context.status.account}:vault:${id}`
      ),
      kms_wrapped_vault_key: kmsWrapped,
      coordinate: coordinate
        ? { provider: coordinate.provider, owner: coordinate.owner, repository: coordinate.repo }
        : null,
    },
  })
  rememberVaultRow(config, row)
  invalidateVaultList(config)
  vaultKeys.set(vaultRowCacheKey(config, id), key)
  return encryptedVault(config, row, async () => null)
}

async function coordinateRead(
  config: VaultConfig,
  ref: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ value: string }> {
  const match = ref.match(/^vlt:\/\/([^/]+)\/([^/]+)(?:\/([^/]+))?\/([^/]+)$/)
  if (!match) throw new Error("Invalid vlt:// reference")
  const provider = match[1]!.toLowerCase()
  const owner = match[2]!.toLowerCase()
  const repository = match[3]?.toLowerCase() ?? null
  const name = decodeURIComponent(match[4]!)
  const query = new URLSearchParams({ provider, owner })
  if (repository) query.set("repository", repository)
  const rows = await jsonRequest<VaultRow[]>(config, `/v1/coordinates?${query}`)
  const candidates: { vault_id: string; locator?: string; item_id?: string }[] = []
  for (const row of rows) {
    candidates.push({ vault_id: row.id, locator: await itemLocator(await vaultKey(config, row, fetchOidcToken), name) })
    const plain = (await itemRows(config, row.id)).find((item) =>
      item.content_mode === "plain" && item.title === name
    )
    if (plain) candidates.push({ vault_id: row.id, item_id: plain.id })
  }
  const item = await jsonRequest<ItemRow>(config, "/v1/coordinates/read", {
    method: "POST",
    body: { provider, owner, repository, candidates },
  })
  const vault = rows.find((row) => row.id === item.vault_id)!
  const decrypted = await encryptedItem(config, item, vault, fetchOidcToken)
  const fields = decrypted.fields as { id?: string; value?: string }[] | undefined
  const field = fields?.find((entry) => entry.id === "value") ?? fields?.[0]
  if (typeof field?.value !== "string") throw new Error("Secret item has no value field")
  return { value: field.value }
}

export async function handleSecretsApi<T>(
  config: VaultConfig,
  path: string,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ handled: boolean; value?: T }> {
  if (!path.startsWith("/v1/read")) return { handled: false }
  const context = await cryptoContext(config, false)
  if (!context.status.initialized) throw new Error("Account encryption is not initialized")
  const ref = new URL(path, "https://cvlt.local").searchParams.get("ref")
  if (!ref) throw new Error("Missing ref")
  return { handled: true, value: await coordinateRead(config, ref, fetchOidcToken) as T }
}

export async function handleApi<T>(
  config: VaultConfig,
  path: string,
  options: RequestOptions,
  fetchOidcToken: OidcTokenFetcher
): Promise<{ handled: boolean; value?: T }> {
  const url = new URL(path, "https://cvlt.local")
  const method = options.method || "GET"
  const parts = url.pathname.split("/").filter(Boolean)
  if (parts[0] !== "v1" || parts[1] !== "vaults") return { handled: false }
  if (parts.length === 2) {
    if (method === "POST") {
      return { handled: true, value: await createVault(config, options.body as Record<string, unknown>) as T }
    }
    const rows = await vaultRows(config)
    const vaults = await Promise.all(rows.map((row) => encryptedVault(config, row, fetchOidcToken)))
    return {
      handled: true,
      value: filterVaults(vaults, url.searchParams) as T,
    }
  }

  const vaultId = parts[2]!
  const vault = await findVaultRow(config, vaultId)
  if (parts.length === 3) {
    if (method === "DELETE") {
      await jsonRequest(config, `/v1/vaults/${vaultId}`, { method: "DELETE" })
      removeVaultRow(config, vaultId)
      return { handled: true, value: undefined as T }
    }
    if (method === "PUT") {
      if (vault.content_mode === "plain") {
        return {
          handled: true,
          value: await jsonRequest<T>(config, `/v1/vaults/${vaultId}`, {
            method: "PUT",
            body: options.body,
          }),
        }
      }
      const current = await encryptedVault(config, vault, fetchOidcToken)
      const overview: VaultOverview = {
        name: String((options.body as Record<string, unknown>).name ?? current.name),
        description: String((options.body as Record<string, unknown>).description ?? current.description ?? ""),
        type: String(current.type ?? "USER_CREATED"),
        ...((options.body as Record<string, unknown>).password_rotation_days !== undefined
          ? { password_rotation_days: (options.body as Record<string, unknown>).password_rotation_days as number | null }
          : current.password_rotation_days !== undefined
            ? { password_rotation_days: current.password_rotation_days as number }
            : {}),
      }
      const row = await jsonRequest<VaultRow>(config, `/v1/vaults/${vaultId}`, {
        method: "PUT",
        body: {
          overview: await encryptJson(
            overview,
            await vaultKey(config, vault, fetchOidcToken),
            `cvlt:v1:vault:${vaultId}:overview`
          ),
        },
      })
      rememberVaultRow(config, row)
      invalidateVaultList(config)
      return { handled: true, value: await encryptedVault(config, row, fetchOidcToken) as T }
    }
    return { handled: true, value: await encryptedVault(config, vault, fetchOidcToken) as T }
  }

  if (parts[3] !== "items") return { handled: false }
  if (parts.length === 4) {
    if (method === "POST") {
      return {
        handled: true,
        value: await createItem(config, vault, options.body as Record<string, unknown>, fetchOidcToken) as T,
      }
    }
    const rows = await itemRows(config, vaultId)
    const items = await Promise.all(rows.map((row) => encryptedItem(config, row, vault, fetchOidcToken)))
    return { handled: true, value: filterItems(items, url.searchParams) as T }
  }

  if (parts[4] === "resolve" && parts.length === 5 && method === "POST") {
    const title = (options.body as Record<string, unknown> | undefined)?.title
    if (typeof title !== "string" || title.length === 0) throw new Error("Item title is required")
    let row: ItemRow
    try {
      row = await jsonRequest<ItemRow>(config, `/v1/vaults/${vaultId}/items/resolve`, {
        method: "POST",
        body: vault.content_mode === "plain"
          ? { title }
          : { locator: await itemLocator(await vaultKey(config, vault, fetchOidcToken), title) },
      })
    } catch (error) {
      if (!(error instanceof VaultApiError) || error.status !== 404 || vault.content_mode === "plain") throw error
      const matches = await Promise.all((await itemRows(config, vaultId)).map(
        (candidate) => encryptedItem(config, candidate, vault, fetchOidcToken)
      ))
      const match = matches.find((candidate) => candidate.title === title)
      if (!match) throw error
      row = await findItemRow(config, vaultId, String(match.id))
    }
    rememberItemRow(config, row)
    return { handled: true, value: await encryptedItem(config, row, vault, fetchOidcToken) as T }
  }

  const itemId = parts[4]!
  if (parts[5] === "files") {
    if (parts.length === 6 && method === "GET") {
      const rows = await fileRows(config, vaultId, itemId)
      return {
        handled: true,
        value: await Promise.all(rows.map((row) => encryptedFileInfo(config, row, vault, fetchOidcToken))) as T,
      }
    }
    return { handled: false }
  }

  const row = await findItemRow(config, vaultId, itemId)
  if (parts[5] === "move" && method === "POST") {
    const destinationId = String((options.body as Record<string, unknown>).vault)
    const destination = await findVaultRow(config, destinationId)
    const current = await encryptedItem(config, row, vault, fetchOidcToken)
    const attachments = await fileRows(config, vaultId, itemId)
    const contents = await Promise.all(
      attachments.map((file) => downloadEncryptedFile(config, vaultId, itemId, file.id, fetchOidcToken))
    )
    const created = await createItem(config, destination, current, fetchOidcToken)
    for (const file of contents) {
      await uploadEncryptedFile(
        config,
        destinationId,
        String(created.id),
        String(file.info.name),
        String(file.info.content_type ?? "application/octet-stream"),
        file.content,
        fetchOidcToken
      )
    }
    await jsonRequest(config, `/v1/vaults/${vaultId}/items/${itemId}`, { method: "DELETE" })
    removeItemRow(config, vaultId, itemId)
    invalidateVaultRow(config, vaultId)
    return { handled: true, value: created as T }
  }
  if (method === "DELETE") {
    await jsonRequest(config, `/v1/vaults/${vaultId}/items/${itemId}`, { method: "DELETE" })
    removeItemRow(config, vaultId, itemId)
    invalidateVaultRow(config, vaultId)
    return { handled: true, value: undefined as T }
  }
  if (method === "PUT") {
    return {
      handled: true,
      value: await updateItem(config, vault, row, options.body as Record<string, unknown>, fetchOidcToken) as T,
    }
  }
  return { handled: true, value: await encryptedItem(config, row, vault, fetchOidcToken) as T }
}

export async function e2eeDoctor(config: VaultConfig): Promise<{
  initialized: boolean
  client_registered: boolean
  vaults: number
  items: number
  kms_ready: boolean
}> {
  const context = await cryptoContext(config, false)
  const rows = await vaultRows(config)
  let items = 0
  for (const row of rows) {
    items += (await itemRows(config, row.id)).length
  }
  return {
    initialized: context.status.initialized,
    client_registered: isOidc() || !!context.status.client,
    vaults: rows.length,
    items,
    kms_ready: !!(
      context.status.kms.public_key_pem
      && context.status.kms.wif_audience
      && context.status.kms.key_version
      && rows.every((row) => row.kms_wrapped_vault_key)
    ),
  }
}

// ── Client installations ────────────────────────────────────────────────────
//
// Management operations prove possession of an already registered
// installation's private key. The service issues a short-lived, single-use
// RSA-OAEP challenge bound to the account, the current client ID, the HTTP
// method, the wire pathname, and the SHA-256 of the exact request-body bytes.
// The private key and the account key never leave this process.

export type ClientSummary = {
  id: string
  name: string | null
  platform: string | null
  created_at: string
  is_current: boolean
}

export type EnrollmentRequestResult = {
  status: "request" | "already-registered"
  origin: string
  account: string
  client_id: string
  fingerprint: string
  platform: string
  name: string | null
  /** Present only for status "request". */
  request: string | null
  created_key: boolean
}

export type EnrollmentApprovalDetails = {
  origin: string
  account: string
  client_id: string
  fingerprint: string
  platform: string
  name: string | null
  current_client_id: string
}

export type EnrollmentApprovalResult = {
  status: "approved" | "declined"
  details: EnrollmentApprovalDetails
}

type ManagementContext = { device: DeviceKey; status: Status; accountKey: Uint8Array | null }

type Challenge = { id: string; ciphertext: string; expires_at: string }

/** The already-serialized bytes as a standalone buffer, so fetch cannot re-encode them. */
function requestBody(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

async function managementContext(config: VaultConfig): Promise<ManagementContext> {
  if (isOidc()) throw new Error("GitHub Actions cannot manage client installations")
  const context = await cryptoContext(config, false)
  if (!context.status.initialized) throw new Error(NOT_INITIALIZED_MESSAGE)
  if (!context.device || !context.status.client) throw new Error(NOT_REGISTERED_MESSAGE)
  return { device: context.device, status: context.status, accountKey: context.accountKey }
}

/**
 * Run one management operation under a fresh possession proof.
 *
 * The body is serialized exactly once: the digest sent to the challenge route
 * and the bytes put on the wire are the same buffer, so no re-serialization
 * can change whitespace, property order, or encoding between the two.
 */
async function managementRequest<T>(
  config: VaultConfig,
  device: DeviceKey,
  account: string,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown
): Promise<T> {
  const bodyBytes = body === undefined ? null : encoder.encode(JSON.stringify(body))
  const pathname = new URL(`${config.baseUrl}${path}`).pathname
  const challenge = await jsonRequest<Challenge>(
    config,
    "/v1/clients/challenges",
    {
      method: "POST",
      body: {
        client_id: device.clientId,
        method,
        path: pathname,
        body_sha256: bodyBytes ? await sha256Hex(bodyBytes) : EMPTY_BODY_SHA256,
      },
    },
    { "X-CVLT-Client-ID": device.clientId }
  )
  const proof = await decryptManagementChallenge(challenge.ciphertext, device.privateKey, account, challenge.id)
  const headers: Record<string, string> = {
    ...authHeaders(config, device),
    "X-CVLT-Challenge-ID": challenge.id,
    "X-CVLT-Challenge-Proof": proof,
  }
  if (bodyBytes) headers["Content-Type"] = "application/json"
  const response = await fetch(`${config.baseUrl}${path}`, {
    method,
    headers,
    ...(bodyBytes ? { body: requestBody(bodyBytes) } : {}),
  })
  if (!response.ok) throw new VaultApiError(response.status, await errorMessage(response))
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

/**
 * Produce the public enrollment request for this installation.
 *
 * Load-or-create: the single device key of the selected Vault origin is
 * reused, never overwritten. A key is generated only when the origin has no
 * key at all, so enrolling the same machine into a second personal or
 * organization account keeps every existing registration readable.
 */
export async function createClientEnrollmentRequest(
  config: VaultConfig,
  name?: string
): Promise<EnrollmentRequestResult> {
  if (isOidc()) throw new Error("GitHub Actions cannot enroll a client installation")
  const origin = normalizeVaultOrigin(config.baseUrl)
  const displayName = normalizeClientName(name)
  const platform = process.platform
  const existing = await originDeviceKey(origin)
  const status = await readStatus(config, existing)
  if (!status.initialized) throw new Error(NOT_INITIALIZED_MESSAGE)
  const device = existing ?? await generateDeviceKey()
  if (!existing) {
    await saveDeviceKey(origin, device)
    rememberDeviceKey(origin, device)
  }
  const common = {
    origin,
    account: status.account,
    client_id: device.clientId,
    fingerprint: formatFingerprint(device.clientId),
    platform,
    name: displayName ?? null,
    created_key: !existing,
  }
  // A historical Node SDK stored the runtime's JWK member order in the client
  // ID. If that exact ID is already registered, it remains safe and usable;
  // canonical IDs are required only when creating a new enrollment request.
  if (status.client) return { ...common, status: "already-registered", request: null }
  if (await publicKeyFingerprint(device.publicKey) !== device.clientId) {
    throw new Error(
      "This installation key predates canonical client IDs and cannot create a new enrollment request. Use a fresh installation, or keep this registered installation until coordinated key rotation is available"
    )
  }
  const request: EnrollmentRequest = {
    version: 1,
    origin,
    account: status.account,
    client_id: device.clientId,
    public_key: assertPublicJwk(device.publicKey),
    platform,
    ...(displayName === undefined ? {} : { name: displayName }),
  }
  return { ...common, status: "request", request: encodeEnrollmentRequest(request) }
}

/**
 * Approve an enrollment request from an already registered installation.
 *
 * The request must decode cleanly, carry a public key whose canonical
 * fingerprint is its client ID, and match this installation's Vault origin and
 * canonical account. `confirm` receives those details for display and must
 * return true before anything is registered.
 */
export async function approveClientEnrollment(
  config: VaultConfig,
  token: string,
  confirm: (details: EnrollmentApprovalDetails) => boolean | Promise<boolean>
): Promise<EnrollmentApprovalResult> {
  const request = await decodeEnrollmentRequest(token)
  const { device, status, accountKey } = await managementContext(config)
  const origin = normalizeVaultOrigin(config.baseUrl)
  if (request.origin !== origin) {
    throw new Error(`Enrollment request targets ${request.origin}, but this installation is using ${origin}`)
  }
  if (request.account !== status.account) {
    throw new Error(`Enrollment request is for account ${request.account}, but this installation is using ${status.account}`)
  }
  if (request.client_id === device.clientId) {
    throw new Error("That enrollment request was created by this installation")
  }
  if (!accountKey) throw new Error("This installation cannot decrypt the account key")
  const details: EnrollmentApprovalDetails = {
    origin,
    account: status.account,
    client_id: request.client_id,
    fingerprint: formatFingerprint(request.client_id),
    platform: request.platform,
    name: request.name ?? null,
    current_client_id: device.clientId,
  }
  if (!(await confirm(details))) return { status: "declined", details }
  await managementRequest(config, device, status.account, "POST", "/v1/clients", {
    id: request.client_id,
    public_key: request.public_key,
    wrapped_account_key: await wrapAccountKeyForDevice(accountKey, request.public_key, status.account),
    platform: request.platform,
    ...(request.name === undefined ? {} : { name: request.name }),
  })
  return { status: "approved", details }
}

/** Active installations of the authenticated account. Never returns keys or envelopes. */
export async function listClients(config: VaultConfig): Promise<ClientSummary[]> {
  const { device, status } = await managementContext(config)
  return managementRequest<ClientSummary[]>(config, device, status.account, "GET", "/v1/clients")
}

export async function revokeClient(
  config: VaultConfig,
  clientId: string
): Promise<{ client_id: string; account: string; origin: string }> {
  const { device, status } = await managementContext(config)
  if (clientId === device.clientId) {
    throw new Error(
      "Revoking the current installation from itself is not allowed. Revoke it from another registered installation, or run cvlt recover to reset every installation"
    )
  }
  await managementRequest<void>(
    config,
    device,
    status.account,
    "DELETE",
    `/v1/clients/${encodeURIComponent(clientId)}`
  )
  return { client_id: clientId, account: status.account, origin: normalizeVaultOrigin(config.baseUrl) }
}

export async function startRecovery(config: VaultConfig): Promise<void> {
  await jsonRequest(config, "/v1/recovery/start", { method: "POST" })
}

export async function completeRecovery(
  config: VaultConfig,
  emailCode: string,
  recoveryCode: string
): Promise<void> {
  const status = await readStatus(config, null)
  const verified = await jsonRequest<{ recovery_token: string; recovery: RecoveryEnvelope }>(
    config,
    "/v1/recovery/verify",
    { method: "POST", body: { code: emailCode } }
  )
  const accountKey = await openRecoveryEnvelope(verified.recovery, recoveryCode, status.account)
  const origin = new URL(config.baseUrl).origin
  const existing = await originDeviceKey(origin)
  const device = existing ?? await generateDeviceKey()
  if (!existing) {
    await saveDeviceKey(origin, device)
    rememberDeviceKey(origin, device)
  }
  const replacementRecovery = await createRecoveryEnvelope(accountKey, status.account)
  await jsonRequest(config, "/v1/recovery/complete", {
    method: "POST",
    body: {
      recovery_token: verified.recovery_token,
      recovery: replacementRecovery.envelope,
      client: {
        id: device.clientId,
        public_key: device.publicKey,
        wrapped_account_key: await wrapAccountKeyForDevice(accountKey, device.publicKey, status.account),
        platform: process.platform,
      },
    },
  })
  process.stderr.write("\nNew Circles Vault recovery code (the previous code and clients are revoked):\n")
  process.stderr.write(`${replacementRecovery.code}\n\n`)
  resetE2eeCaches()
}
