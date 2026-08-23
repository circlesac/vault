/**
 * Enrollment requests — the public registration material a fresh installation
 * hands to an already registered one.
 *
 * A request is deterministic, versioned, base64url-encoded JSON. It carries
 * only public registration material: the Vault origin, the canonical account,
 * the client ID, the public-only JWK, the platform, and an optional display
 * name. It is never a bearer credential — approval additionally requires
 * origin/account matching, fingerprint comparison, explicit confirmation, and
 * proof that the approver possesses an active installation's private key.
 */

import { decodeBase64, encodeBase64, publicKeyFingerprint } from "./e2ee-crypto"

export const ENROLLMENT_REQUEST_VERSION = 1
export const MAX_CLIENT_NAME_LENGTH = 64

export type EnrollmentRequest = {
  version: 1
  origin: string
  account: string
  client_id: string
  public_key: JsonWebKey
  platform: string
  name?: string
}

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })

/** Property order of a request, and of the public JWK inside it. Both are fixed
 * so the same installation and arguments always produce the same token. */
const REQUEST_FIELDS = ["version", "origin", "account", "client_id", "public_key", "platform", "name"] as const
const PUBLIC_JWK_FIELDS = ["alg", "e", "ext", "key_ops", "kty", "n"] as const

const ACCOUNT_PATTERN = /^(?:org|user):[0-9]+$/
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/
const PLATFORM_PATTERN = /^[a-z0-9][a-z0-9._-]{0,31}$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/
const NAME_PATTERN = /^[\x20-\x7e]+$/

/** Vault origin as the key store and the request both spell it: scheme + host. */
export function normalizeVaultOrigin(baseUrl: string): string {
  const url = new URL(baseUrl)
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`Vault origin ${baseUrl} is not an HTTP origin`)
  }
  return url.origin
}

/**
 * Fingerprint as it is displayed for human comparison across two machines.
 * Grouped with spaces because base64url itself uses `-` and `_`.
 */
export function formatFingerprint(clientId: string): string {
  return `SHA256:${(clientId.match(/.{1,8}/g) ?? []).join(" ")}`
}

export function normalizeClientName(name: string | undefined | null): string | undefined {
  if (name === undefined || name === null) return undefined
  const trimmed = name.trim()
  if (trimmed.length === 0) return undefined
  if (trimmed.length > MAX_CLIENT_NAME_LENGTH) {
    throw new Error(`Client name must be at most ${MAX_CLIENT_NAME_LENGTH} characters`)
  }
  if (!NAME_PATTERN.test(trimmed)) throw new Error("Client name must be printable ASCII")
  return trimmed
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/**
 * Enforce the public-key contract exactly: RSA-OAEP with a 3072-bit modulus,
 * SHA-256, exponent 65537, public operations only, no private RSA parameters,
 * and no extra properties. Returns the canonically ordered JWK.
 */
export function assertPublicJwk(value: unknown): JsonWebKey {
  if (!isPlainObject(value)) throw new Error("public_key must be a JWK object")
  const keys = Object.keys(value).sort()
  const expected = [...PUBLIC_JWK_FIELDS].sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`public_key must contain exactly ${expected.join(", ")}`)
  }
  if (value.kty !== "RSA") throw new Error("public_key must be an RSA key")
  if (value.alg !== "RSA-OAEP-256") throw new Error("public_key must be RSA-OAEP with SHA-256")
  if (value.e !== "AQAB") throw new Error("public_key must use exponent 65537")
  if (value.ext !== true) throw new Error("public_key must be extractable")
  const keyOps = value.key_ops
  if (!Array.isArray(keyOps) || keyOps.length !== 1 || keyOps[0] !== "encrypt") {
    throw new Error("public_key must allow public operations only")
  }
  if (typeof value.n !== "string" || !BASE64URL_PATTERN.test(value.n)) {
    throw new Error("public_key modulus must be base64url")
  }
  const modulus = decodeBase64(value.n)
  if (modulus.byteLength !== 384) throw new Error("public_key must have a 3072-bit modulus")
  if ((modulus[0]! & 0x80) === 0) throw new Error("public_key must have a 3072-bit modulus")
  if ((modulus[modulus.byteLength - 1]! & 1) === 0) throw new Error("public_key modulus must be odd")
  return Object.fromEntries(PUBLIC_JWK_FIELDS.map((field) => [field, value[field]])) as JsonWebKey
}

/** Name validation inside a request reports one message for every rejection. */
function normalized(name: string): string | undefined {
  try {
    return normalizeClientName(name)
  } catch {
    return undefined
  }
}

function assertRequestShape(value: unknown): EnrollmentRequest {
  if (!isPlainObject(value)) throw new Error("Enrollment request is malformed")
  if (value.version !== ENROLLMENT_REQUEST_VERSION) {
    throw new Error(`Unsupported enrollment request version: ${JSON.stringify(value.version)}`)
  }
  for (const key of Object.keys(value)) {
    if (!(REQUEST_FIELDS as readonly string[]).includes(key)) {
      throw new Error(`Enrollment request contains an unsupported field: ${key}`)
    }
  }
  if (typeof value.origin !== "string" || normalizeVaultOrigin(value.origin) !== value.origin) {
    throw new Error("Enrollment request origin is not a normalized Vault origin")
  }
  if (typeof value.account !== "string" || !ACCOUNT_PATTERN.test(value.account)) {
    throw new Error("Enrollment request account is not a canonical account")
  }
  if (typeof value.client_id !== "string" || !CLIENT_ID_PATTERN.test(value.client_id)) {
    throw new Error("Enrollment request client ID is not a public-key fingerprint")
  }
  if (typeof value.platform !== "string" || !PLATFORM_PATTERN.test(value.platform)) {
    throw new Error("Enrollment request platform is invalid")
  }
  if (value.name !== undefined && (typeof value.name !== "string" || normalized(value.name) !== value.name)) {
    throw new Error("Enrollment request name is invalid")
  }
  return {
    version: ENROLLMENT_REQUEST_VERSION,
    origin: value.origin,
    account: value.account,
    client_id: value.client_id,
    public_key: assertPublicJwk(value.public_key),
    platform: value.platform,
    ...(value.name === undefined ? {} : { name: value.name as string }),
  }
}

/** Deterministic JSON for a validated request: fixed field order, no whitespace. */
export function canonicalEnrollmentJson(request: EnrollmentRequest): string {
  const validated = assertRequestShape(request)
  const ordered: Record<string, unknown> = {}
  for (const field of REQUEST_FIELDS) {
    const value = (validated as Record<string, unknown>)[field]
    if (value !== undefined) ordered[field] = value
  }
  return JSON.stringify(ordered)
}

export function encodeEnrollmentRequest(request: EnrollmentRequest): string {
  return encodeBase64(encoder.encode(canonicalEnrollmentJson(request)))
}

/**
 * Decode and fully validate a request. Rejects malformed tokens, unknown
 * versions, invalid or private JWKs, and any client ID that is not the
 * canonical fingerprint of the enclosed public key.
 */
export async function decodeEnrollmentRequest(token: string): Promise<EnrollmentRequest> {
  const trimmed = token.trim()
  if (!BASE64URL_PATTERN.test(trimmed)) throw new Error("Enrollment request is malformed")
  let parsed: unknown
  try {
    parsed = JSON.parse(decoder.decode(decodeBase64(trimmed)))
  } catch {
    throw new Error("Enrollment request is malformed")
  }
  const request = assertRequestShape(parsed)
  if (await publicKeyFingerprint(request.public_key) !== request.client_id) {
    throw new Error("Enrollment request client ID does not match its public key")
  }
  return request
}
