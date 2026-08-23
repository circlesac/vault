/**
 * A strict in-memory stand-in for the Vault service's client-management
 * surface, used by the client tests. It implements the wire contract exactly
 * as specified — bindings over method, wire pathname and exact request-body
 * bytes, single-use challenges, five outstanding per account/client — so the
 * client is verified against the protocol rather than against a mock that
 * agrees with it.
 *
 * Not part of the published SDK: nothing under `src/index.ts` or `src/cli.ts`
 * imports it.
 */

import {
  encryptManagementChallenge,
  publicKeyFingerprint,
  randomKey,
  sha256Hex,
  wrapAccountKeyForDevice,
  type DeviceKey,
  type RsaEnvelope,
} from "./e2ee-crypto"
import { assertPublicJwk } from "./client-enrollment"

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export type ClientRow = {
  id: string
  publicKey: JsonWebKey
  wrappedAccountKey: RsaEnvelope
  platform: string | null
  name: string | null
  createdAt: string
  revoked: boolean
}

type ChallengeRow = {
  id: string
  clientId: string
  proofHash: string
  method: string
  path: string
  bodySha256: string
  expiresAt: number
}

export type FakeVaultRequest = {
  method: string
  path: string
  body: string | null
  clientId: string | null
  challengeId: string | null
  hasProof: boolean
}

export type FakeVaultOptions = {
  account?: string
  orgPrefix?: string | null
  initialized?: boolean
  challengeTtlMs?: number
  maxOutstandingChallenges?: number
}

export type FakeVault = {
  account: string
  accountKey: Uint8Array
  prefix: string
  clients: Map<string, ClientRow>
  requests: FakeVaultRequest[]
  outstandingChallenges(): number
  setClock(clock: () => number): void
  setInitialized(value: boolean): void
  register(device: DeviceKey, extra?: { name?: string | null; platform?: string | null; revoked?: boolean }): Promise<void>
  handle(request: Request): Promise<Response>
  /** Drop-in replacement for globalThis.fetch. */
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>
}

function fail(status: number, message: string): Response {
  return Response.json({ status, message }, { status })
}

export function createFakeVault(options: FakeVaultOptions = {}): FakeVault {
  const account = options.account ?? "user:1"
  const prefix = options.orgPrefix ? `/${options.orgPrefix}` : ""
  const ttlMs = options.challengeTtlMs ?? 5 * 60 * 1000
  const maxOutstanding = options.maxOutstandingChallenges ?? 5
  const accountKey = randomKey()
  const clients = new Map<string, ClientRow>()
  const challenges = new Map<string, ChallengeRow>()
  const requests: FakeVaultRequest[] = []
  let initialized = options.initialized ?? true
  let clock = () => Date.now()
  let challengeCounter = 0

  function active(clientId: string | null | undefined): ClientRow | null {
    if (!clientId) return null
    const row = clients.get(clientId)
    return row && !row.revoked ? row : null
  }

  /** Opportunistic expiry sweep for one account/client pair. */
  function pruneExpired(clientId: string) {
    for (const [id, row] of challenges) {
      if (row.clientId === clientId && row.expiresAt <= clock()) challenges.delete(id)
    }
  }

  async function createChallenge(request: Request, bodyBytes: Uint8Array): Promise<Response> {
    const callerId = request.headers.get("X-CVLT-Client-ID")
    const caller = active(callerId)
    if (!caller) return fail(403, "Current client is not registered")
    let body: { client_id?: unknown; method?: unknown; path?: unknown; body_sha256?: unknown }
    try {
      body = JSON.parse(decoder.decode(bodyBytes))
    } catch {
      return fail(400, "Malformed challenge request")
    }
    if (body.client_id !== caller.id) return fail(403, "Challenge client_id must be the current client")
    if (typeof body.method !== "string" || !["GET", "POST", "DELETE"].includes(body.method)) {
      return fail(400, "Challenge method is invalid")
    }
    if (typeof body.path !== "string" || !body.path.startsWith("/")) return fail(400, "Challenge path is invalid")
    if (typeof body.body_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(body.body_sha256)) {
      return fail(400, "Challenge body_sha256 is invalid")
    }
    pruneExpired(caller.id)
    const outstanding = [...challenges.values()].filter((row) => row.clientId === caller.id).length
    if (outstanding >= maxOutstanding) return fail(429, "Too many outstanding client management challenges")
    const id = `chl_${++challengeCounter}`
    // The stored row keeps only the proof digest; the plaintext is returned
    // once, encrypted to the registered public key, and never again.
    const proof = Buffer.from(randomKey()).toString("base64url")
    challenges.set(id, {
      id,
      clientId: caller.id,
      proofHash: await sha256Hex(encoder.encode(proof)),
      method: body.method,
      path: body.path,
      bodySha256: body.body_sha256,
      expiresAt: clock() + ttlMs,
    })
    return Response.json({
      id,
      ciphertext: await encryptManagementChallenge(proof, caller.publicKey, account, id),
      expires_at: new Date(clock() + ttlMs).toISOString(),
    })
  }

  /** Atomically validate and consume the bound single-use proof. */
  async function consumeProof(
    request: Request,
    path: string,
    bodyBytes: Uint8Array
  ): Promise<{ caller: ClientRow } | Response> {
    const caller = active(request.headers.get("X-CVLT-Client-ID"))
    if (!caller) return fail(403, "Current client is not registered")
    pruneExpired(caller.id)
    const challengeId = request.headers.get("X-CVLT-Challenge-ID")
    const proof = request.headers.get("X-CVLT-Challenge-Proof")
    if (!challengeId || !proof) return fail(403, "Client management proof is required")
    const row = challenges.get(challengeId)
    if (!row) return fail(403, "Client management proof is invalid")
    if (row.expiresAt <= clock()) {
      challenges.delete(challengeId)
      return fail(403, "Client management proof has expired")
    }
    if (row.clientId !== caller.id) return fail(403, "Client management proof is invalid")
    if (await sha256Hex(encoder.encode(proof)) !== row.proofHash) {
      return fail(403, "Client management proof is invalid")
    }
    if (row.method !== request.method) return fail(403, "Client management proof is bound to another method")
    if (row.path !== path) return fail(403, "Client management proof is bound to another path")
    if (row.bodySha256 !== await sha256Hex(bodyBytes)) {
      return fail(403, "Client management proof is bound to another request body")
    }
    challenges.delete(challengeId)
    return { caller }
  }

  async function registerClient(caller: ClientRow, bodyBytes: Uint8Array): Promise<Response> {
    let body: Record<string, unknown>
    try {
      body = JSON.parse(decoder.decode(bodyBytes)) as Record<string, unknown>
    } catch {
      return fail(400, "Malformed client registration")
    }
    let publicKey: JsonWebKey
    try {
      publicKey = assertPublicJwk(body.public_key)
    } catch (error) {
      return fail(400, (error as Error).message)
    }
    if (typeof body.id !== "string" || await publicKeyFingerprint(publicKey) !== body.id) {
      return fail(400, "client id does not match its public key")
    }
    if (body.wrapped_account_key === undefined) return fail(400, "wrapped_account_key is required")
    if (body.name !== undefined && (typeof body.name !== "string" || body.name.length > 64)) {
      return fail(400, "client name is invalid")
    }
    const platform = typeof body.platform === "string" ? body.platform : null
    const name = typeof body.name === "string" ? body.name : null
    const existing = clients.get(body.id)
    if (existing && JSON.stringify(existing.publicKey) !== JSON.stringify(publicKey)) {
      return fail(409, "Client ID is already registered with a different public key")
    }
    if (existing && !existing.revoked) {
      return Response.json({ id: existing.id, status: "active" })
    }
    clients.set(body.id, {
      id: body.id,
      publicKey,
      wrappedAccountKey: body.wrapped_account_key as RsaEnvelope,
      platform,
      name,
      createdAt: existing?.createdAt ?? new Date(clock()).toISOString(),
      revoked: false,
    })
    return Response.json({ id: body.id, status: existing ? "reactivated" : "created" }, { status: 201 })
  }

  async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const path = url.pathname
    const bodyBytes = new Uint8Array(await request.arrayBuffer())
    requests.push({
      method: request.method,
      path,
      body: bodyBytes.byteLength ? decoder.decode(bodyBytes) : null,
      clientId: request.headers.get("X-CVLT-Client-ID"),
      challengeId: request.headers.get("X-CVLT-Challenge-ID"),
      hasProof: !!request.headers.get("X-CVLT-Challenge-Proof"),
    })
    if (!request.headers.get("Authorization")?.startsWith("Bearer ")) return fail(401, "Unauthorized")
    if (!path.startsWith(`${prefix}/v1/`)) return fail(404, `No route for ${path}`)
    const route = path.slice(prefix.length)

    if (route === "/v1/status" && request.method === "GET") {
      const client = active(request.headers.get("X-CVLT-Client-ID"))
      return Response.json({
        account,
        initialized,
        format_version: initialized ? 1 : null,
        client: client
          ? {
              id: client.id,
              public_key: client.publicKey,
              wrapped_account_key: client.wrappedAccountKey,
              platform: client.platform,
              created_at: client.createdAt,
            }
          : null,
        kms: { public_key_pem: null, wif_audience: null, key_version: null },
      })
    }

    if (route === "/v1/clients/challenges" && request.method === "POST") {
      return createChallenge(request, bodyBytes)
    }

    if (route === "/v1/clients" || route.startsWith("/v1/clients/")) {
      const consumed = await consumeProof(request, path, bodyBytes)
      if (consumed instanceof Response) return consumed
      const { caller } = consumed
      if (route === "/v1/clients" && request.method === "GET") {
        return Response.json(
          [...clients.values()]
            .filter((row) => !row.revoked)
            .map((row) => ({
              id: row.id,
              name: row.name,
              platform: row.platform,
              created_at: row.createdAt,
              is_current: row.id === caller.id,
            }))
        )
      }
      if (route === "/v1/clients" && request.method === "POST") return registerClient(caller, bodyBytes)
      if (request.method === "DELETE") {
        const target = decodeURIComponent(route.slice("/v1/clients/".length))
        if (target === caller.id) return fail(403, "Cannot revoke the current client")
        const row = clients.get(target)
        if (!row || row.revoked) return fail(404, "Client not found")
        row.revoked = true
        return new Response(null, { status: 204 })
      }
    }
    return fail(404, `No route for ${request.method} ${path}`)
  }

  return {
    account,
    accountKey,
    prefix,
    clients,
    requests,
    outstandingChallenges: () => challenges.size,
    setClock: (next) => { clock = next },
    setInitialized: (value) => { initialized = value },
    async register(device, extra = {}) {
      clients.set(device.clientId, {
        id: device.clientId,
        publicKey: device.publicKey,
        wrappedAccountKey: await wrapAccountKeyForDevice(accountKey, device.publicKey, account),
        platform: extra.platform === undefined ? "darwin" : extra.platform,
        name: extra.name ?? null,
        createdAt: "2026-08-23T00:00:00.000Z",
        revoked: extra.revoked ?? false,
      })
    },
    handle,
    async fetch(input, init) {
      const request = input instanceof Request && init === undefined
        ? input
        : new Request(String(input), init)
      return handle(request)
    },
  }
}
