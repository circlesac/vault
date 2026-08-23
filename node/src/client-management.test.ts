import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test"
import {
  approveClientEnrollment,
  completeRecovery,
  createClientEnrollmentRequest,
  handleApi,
  handleSecretsApi,
  listClients,
  resetE2eeCaches,
  revokeClient,
  VaultApiError,
  type VaultConfig,
} from "./e2ee-client"
import { decodeEnrollmentRequest, encodeEnrollmentRequest, formatFingerprint } from "./client-enrollment"
import {
  decodeBase64,
  encodeBase64,
  EMPTY_BODY_SHA256,
  createRecoveryEnvelope,
  generateDeviceKey,
  sha256Hex,
  unwrapAccountKeyForDevice,
  type DeviceKey,
} from "./e2ee-crypto"
import * as keyStore from "./key-store"
import { createFakeVault, type FakeVault } from "./fake-vault"

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const realFetch = globalThis.fetch

// Two long-lived installations: A is already registered, B is the fresh PC.
const deviceA = await generateDeviceKey()
const deviceB = await generateDeviceKey()

// The device key store is swapped for an in-memory one. Bun resolves
// spawnSync executables from the startup PATH, so a real OS credential store
// cannot be shadowed from inside a test process, and these tests must never
// write to the developer's Keychain, Secret Service, or DPAPI store. Real
// storage is covered by key-store.test.ts and by the two-store CLI test.
const realLoadDeviceKey = keyStore.loadDeviceKey
const realSaveDeviceKey = keyStore.saveDeviceKey
const storedKeys = new Map<string, DeviceKey>()
let loadCalls = 0

async function loadDeviceKey(origin: string): Promise<DeviceKey | null> {
  loadCalls++
  const stored = storedKeys.get(origin)
  return stored ? JSON.parse(JSON.stringify(stored)) as DeviceKey : null
}

async function saveDeviceKey(origin: string, key: DeviceKey): Promise<void> {
  storedKeys.set(origin, JSON.parse(JSON.stringify(key)) as DeviceKey)
}

mock.module("./key-store", () => ({ ...keyStore, loadDeviceKey, saveDeviceKey }))

const environment: Record<string, string | undefined> = {}
let originCounter = 0

function nextOrigin(): string {
  return `https://vault-client-test-${++originCounter}.example`
}

beforeAll(() => {
  for (const name of [
    "OP_CONNECT_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  ]) {
    environment[name] = process.env[name]
  }
  process.env.OP_CONNECT_TOKEN = "test-connect-token"
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
})

afterAll(() => {
  for (const [name, value] of Object.entries(environment)) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
  mock.module("./key-store", () => ({
    ...keyStore,
    loadDeviceKey: realLoadDeviceKey,
    saveDeviceKey: realSaveDeviceKey,
  }))
})

beforeEach(() => {
  storedKeys.clear()
  loadCalls = 0
  resetE2eeCaches()
})

afterEach(() => {
  globalThis.fetch = realFetch
  resetE2eeCaches()
})

type Deployment = { origin: string; vault: FakeVault; config: VaultConfig }

/** One fake deployment, wired into globalThis.fetch. */
function deploy(options: Parameters<typeof createFakeVault>[0] = {}): Deployment {
  const origin = nextOrigin()
  const vault = createFakeVault(options)
  const config: VaultConfig = {
    baseUrl: `${origin}${vault.prefix}`,
    token: "caller-token",
    org: options.orgPrefix ?? null,
  }
  globalThis.fetch = vault.fetch as unknown as typeof fetch
  return { origin, vault, config }
}

/** Route one origin to several accounts, the way an org prefix does in production. */
function route(...vaults: FakeVault[]): void {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
    const path = new URL(request.url).pathname
    const prefixed = vaults
      .filter((vault) => vault.prefix && path.startsWith(`${vault.prefix}/`))
      .sort((left, right) => right.prefix.length - left.prefix.length)[0]
    const match = prefixed ?? vaults.find((vault) => !vault.prefix)
    if (!match) return Response.json({ status: 404, message: `No deployment for ${path}` }, { status: 404 })
    return match.handle(request)
  }) as unknown as typeof fetch
}

function challengeBodies(vault: FakeVault): Record<string, unknown>[] {
  return vault.requests
    .filter((request) => request.path.endsWith("/v1/clients/challenges") && request.body)
    .map((request) => JSON.parse(request.body!) as Record<string, unknown>)
}

const approveAll = () => true

describe("enrollment requests", () => {
  it("creates the origin key once and reuses it for every account on that origin", async () => {
    const origin = nextOrigin()
    const personal = createFakeVault({ account: "user:1" })
    const organization = createFakeVault({ account: "org:7", orgPrefix: "example-org" })
    route(personal, organization)
    const personalConfig: VaultConfig = { baseUrl: origin, token: "caller-token", org: null }
    const orgConfig: VaultConfig = { baseUrl: `${origin}/example-org`, token: "caller-token", org: "example-org" }

    expect(await loadDeviceKey(origin)).toBeNull()
    const first = await createClientEnrollmentRequest(personalConfig, "example-workstation")
    expect(first.status).toBe("request")
    expect(first.created_key).toBe(true)
    expect(first.account).toBe("user:1")
    expect(first.origin).toBe(origin)

    const stored = await loadDeviceKey(origin)
    expect(stored).not.toBeNull()
    expect(stored!.clientId).toBe(first.client_id)

    resetE2eeCaches()
    const second = await createClientEnrollmentRequest(orgConfig, "example-workstation")
    expect(second.status).toBe("request")
    expect(second.created_key).toBe(false)
    expect(second.client_id).toBe(first.client_id)
    expect(second.account).toBe("org:7")
    expect(second.request).not.toBe(first.request)

    // The single origin slot is untouched, so the personal registration that
    // may already exist against this key keeps working.
    expect(await loadDeviceKey(origin)).toEqual(stored!)
    const decoded = await decodeEnrollmentRequest(second.request!)
    expect(decoded.origin).toBe(origin)
    expect(decoded.account).toBe("org:7")
    expect(decoded.public_key).toEqual(stored!.publicKey)
  }, 30_000)

  it("emits the identical request for repeated calls and never overwrites the key", async () => {
    const { origin, config } = deploy()
    await saveDeviceKey(origin, deviceB)

    const first = await createClientEnrollmentRequest(config, "example-workstation")
    const second = await createClientEnrollmentRequest(config, "example-workstation")
    expect(second.request).toBe(first.request)
    expect(second.created_key).toBe(false)
    expect(loadCalls).toBe(1)

    resetE2eeCaches()
    const afterReset = await createClientEnrollmentRequest(config, "example-workstation")
    expect(afterReset.request).toBe(first.request)
    expect(afterReset.created_key).toBe(false)
    expect(loadCalls).toBe(2)
    expect((await loadDeviceKey(origin))!.clientId).toBe(deviceB.clientId)

    resetE2eeCaches()
    const renamed = await createClientEnrollmentRequest(config, "another-name")
    expect(renamed.request).not.toBe(first.request)
    expect(renamed.client_id).toBe(deviceB.clientId)
  }, 30_000)

  it("recovery reuses the origin key instead of orphaning another account", async () => {
    const origin = nextOrigin()
    const config: VaultConfig = { baseUrl: origin, token: "caller-token", org: null }
    await saveDeviceKey(origin, deviceA)
    const accountKey = new Uint8Array(32).fill(0x5a)
    const recovery = await createRecoveryEnvelope(accountKey, "user:1")
    let completedClient: Record<string, unknown> | null = null
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
      const path = new URL(request.url).pathname
      if (path === "/v1/status") {
        return Response.json({
          account: "user:1",
          initialized: true,
          format_version: 1,
          client: null,
          kms: { public_key_pem: null, wif_audience: null, key_version: null },
        })
      }
      if (path === "/v1/recovery/verify") {
        return Response.json({ recovery_token: "verified-recovery-session", recovery: recovery.envelope })
      }
      if (path === "/v1/recovery/complete") {
        completedClient = ((await request.json()) as { client: Record<string, unknown> }).client
        return Response.json({ recovered: true }, { status: 201 })
      }
      return Response.json({ status: 404, message: "not found" }, { status: 404 })
    }) as typeof fetch

    const write = process.stderr.write
    process.stderr.write = (() => true) as typeof process.stderr.write
    try {
      await completeRecovery(config, "12345678", recovery.code)
    } finally {
      process.stderr.write = write
    }
    expect(completedClient).toMatchObject({ id: deviceA.clientId, public_key: deviceA.publicKey })
    expect(await loadDeviceKey(origin)).toEqual(deviceA)
  }, 30_000)

  it("directs an uninitialized account to first-use bootstrap without creating a key", async () => {
    const { origin, config } = deploy({ initialized: false })
    await expect(createClientEnrollmentRequest(config)).rejects.toThrow(
      "Account encryption is not initialized"
    )
    expect(await loadDeviceKey(origin)).toBeNull()
  }, 30_000)

  it("rechecks a missing origin key instead of overwriting one created by another process", async () => {
    const { origin, vault, config } = deploy({ initialized: false })
    await expect(createClientEnrollmentRequest(config)).rejects.toThrow(
      "Account encryption is not initialized"
    )
    expect(loadCalls).toBe(1)

    await saveDeviceKey(origin, deviceB)
    vault.setInitialized(true)
    const result = await createClientEnrollmentRequest(config, "example-workstation")
    expect(result.client_id).toBe(deviceB.clientId)
    expect(result.created_key).toBe(false)
    expect(loadCalls).toBe(2)
    expect(await loadDeviceKey(origin)).toEqual(deviceB)
  }, 30_000)

  it("reports an already registered account instead of emitting a request", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA)

    const result = await createClientEnrollmentRequest(config)
    expect(result.status).toBe("already-registered")
    expect(result.request).toBeNull()
    expect(result.client_id).toBe(deviceA.clientId)
    expect(result.fingerprint).toBe(formatFingerprint(deviceA.clientId))
  }, 30_000)

  it("keeps an already-registered historical Node-order client ID usable", async () => {
    const { origin, vault, config } = deploy()
    const legacy = { ...deviceA, clientId: "historical-node-order-client-id" }
    await saveDeviceKey(origin, legacy)
    await vault.register(legacy)

    const result = await createClientEnrollmentRequest(config)
    expect(result.status).toBe("already-registered")
    expect(result.request).toBeNull()
    expect(result.client_id).toBe(legacy.clientId)
  }, 30_000)

  it("does not recommend destructive recovery for an unregistered historical ID", async () => {
    const { origin, config } = deploy()
    const legacy = { ...deviceA, clientId: "historical-node-order-client-id" }
    await saveDeviceKey(origin, legacy)

    await expect(createClientEnrollmentRequest(config)).rejects.toThrow(
      "predates canonical client IDs"
    )
    await expect(createClientEnrollmentRequest(config)).rejects.not.toThrow("recover")
  }, 30_000)

  it("shows a fingerprint that both machines can compare", async () => {
    const { origin, config } = deploy()
    await saveDeviceKey(origin, deviceB)
    const result = await createClientEnrollmentRequest(config)
    const decoded = await decodeEnrollmentRequest(result.request!)
    expect(result.fingerprint).toBe(formatFingerprint(decoded.client_id))
    expect(decoded.client_id).toBe(deviceB.clientId)
  }, 30_000)

  it("is refused under GitHub Actions OIDC", async () => {
    const { config } = deploy()
    delete process.env.OP_CONNECT_TOKEN
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://github.example/oidc"
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "request-token"
    try {
      await expect(createClientEnrollmentRequest(config)).rejects.toThrow("GitHub Actions cannot enroll")
      await expect(listClients(config)).rejects.toThrow("GitHub Actions cannot manage")
      await expect(revokeClient(config, deviceB.clientId)).rejects.toThrow("GitHub Actions cannot manage")
    } finally {
      process.env.OP_CONNECT_TOKEN = "test-connect-token"
      delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL
      delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
    }
  }, 30_000)
})

describe("approval binding", () => {
  async function registeredApprover(options: Parameters<typeof createFakeVault>[0] = {}) {
    const deployment = deploy(options)
    await saveDeviceKey(deployment.origin, deviceA)
    await deployment.vault.register(deviceA, { name: "approver" })
    return deployment
  }

  function requestFrom(origin: string, account: string, name?: string): string {
    return encodeEnrollmentRequest({
      version: 1,
      origin,
      account,
      client_id: deviceB.clientId,
      public_key: deviceB.publicKey,
      platform: "linux",
      ...(name === undefined ? {} : { name }),
    })
  }

  it("registers the requesting installation after an explicit confirmation", async () => {
    const { origin, vault, config } = await registeredApprover()
    const seen: string[] = []
    const result = await approveClientEnrollment(config, requestFrom(origin, "user:1", "example-workstation"), (details) => {
      seen.push(details.fingerprint, details.account, details.origin, details.name ?? "", details.current_client_id)
      return true
    })

    expect(result.status).toBe("approved")
    expect(seen).toEqual([
      formatFingerprint(deviceB.clientId),
      "user:1",
      origin,
      "example-workstation",
      deviceA.clientId,
    ])
    const row = vault.clients.get(deviceB.clientId)!
    expect(row.revoked).toBe(false)
    expect(row.name).toBe("example-workstation")
    // B receives exactly the account key wrapped to B's own public key.
    expect(await unwrapAccountKeyForDevice(row.wrappedAccountKey, deviceB.privateKey, "user:1"))
      .toEqual(vault.accountKey)
  }, 30_000)

  it("registers nothing when the confirmation is declined", async () => {
    const { origin, vault, config } = await registeredApprover()
    const result = await approveClientEnrollment(config, requestFrom(origin, "user:1"), () => false)
    expect(result.status).toBe("declined")
    expect(vault.clients.has(deviceB.clientId)).toBe(false)
    expect(vault.requests.some((request) => request.method === "POST" && request.path.endsWith("/v1/clients")))
      .toBe(false)
  }, 30_000)

  it("refuses a request from another deployment", async () => {
    const { vault, config } = await registeredApprover()
    await expect(
      approveClientEnrollment(config, requestFrom("https://vault.crcl.es", "user:1"), approveAll)
    ).rejects.toThrow("Enrollment request targets https://vault.crcl.es")
    expect(vault.clients.size).toBe(1)
  }, 30_000)

  it("refuses a request for another account on the same deployment", async () => {
    const { origin, vault, config } = await registeredApprover()
    await expect(approveClientEnrollment(config, requestFrom(origin, "org:7"), approveAll))
      .rejects.toThrow("Enrollment request is for account org:7")
    expect(vault.clients.size).toBe(1)
  }, 30_000)

  it("refuses its own enrollment request", async () => {
    const { origin, config } = await registeredApprover()
    const own = encodeEnrollmentRequest({
      version: 1,
      origin,
      account: "user:1",
      client_id: deviceA.clientId,
      public_key: deviceA.publicKey,
      platform: "darwin",
    })
    await expect(approveClientEnrollment(config, own, approveAll))
      .rejects.toThrow("created by this installation")
  }, 30_000)

  it("refuses malformed, unversioned, and key-mismatched requests before any row exists", async () => {
    const { origin, vault, config } = await registeredApprover()
    const valid = JSON.parse(decoder.decode(decodeBase64(requestFrom(origin, "user:1")))) as Record<string, unknown>
    const retoken = (value: unknown) => encodeBase64(encoder.encode(JSON.stringify(value)))

    await expect(approveClientEnrollment(config, "!!!not-a-token", approveAll)).rejects.toThrow("malformed")
    await expect(approveClientEnrollment(config, retoken({ ...valid, version: 2 }), approveAll))
      .rejects.toThrow("Unsupported enrollment request version")
    await expect(
      approveClientEnrollment(config, retoken({ ...valid, client_id: deviceA.clientId }), approveAll)
    ).rejects.toThrow("client ID does not match its public key")
    await expect(
      approveClientEnrollment(config, retoken({ ...valid, public_key: deviceB.privateKey }), approveAll)
    ).rejects.toThrow("must contain exactly")
    expect(vault.clients.size).toBe(1)
    expect(vault.requests.some((request) => request.method === "POST" && request.path.endsWith("/v1/clients")))
      .toBe(false)
  }, 30_000)

  it("is idempotent when the same request is approved twice", async () => {
    const { origin, vault, config } = await registeredApprover()
    const token = requestFrom(origin, "user:1")
    expect((await approveClientEnrollment(config, token, approveAll)).status).toBe("approved")
    expect((await approveClientEnrollment(config, token, approveAll)).status).toBe("approved")
    expect(vault.clients.size).toBe(2)
    expect([...vault.clients.values()].filter((row) => !row.revoked)).toHaveLength(2)
  }, 30_000)

  it("re-enrolls a revoked installation with a fresh wrapped account key", async () => {
    const { origin, vault, config } = await registeredApprover()
    await vault.register(deviceB, { revoked: true, name: "old-name" })
    const staleEnvelope = vault.clients.get(deviceB.clientId)!.wrappedAccountKey

    const result = await approveClientEnrollment(config, requestFrom(origin, "user:1", "example-workstation"), approveAll)
    expect(result.status).toBe("approved")
    const row = vault.clients.get(deviceB.clientId)!
    expect(row.revoked).toBe(false)
    expect(row.name).toBe("example-workstation")
    expect(row.wrappedAccountKey.ciphertext).not.toBe(staleEnvelope.ciphertext)
    expect(await unwrapAccountKeyForDevice(row.wrappedAccountKey, deviceB.privateKey, "user:1"))
      .toEqual(vault.accountKey)
  }, 30_000)

  it("is refused when this installation is not registered", async () => {
    const { origin, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await expect(approveClientEnrollment(config, requestFrom(origin, "user:1"), approveAll))
      .rejects.toThrow("This installation is not registered")
  }, 30_000)
})

describe("management proof binding", () => {
  async function registered(options: Parameters<typeof createFakeVault>[0] = {}) {
    const deployment = deploy(options)
    await saveDeviceKey(deployment.origin, deviceA)
    await deployment.vault.register(deviceA, { name: "approver" })
    return deployment
  }

  it("hashes the exact bytes it puts on the wire and consumes the challenge", async () => {
    const { origin, vault, config } = await registered()
    await approveClientEnrollment(
      config,
      encodeEnrollmentRequest({
        version: 1,
        origin,
        account: "user:1",
        client_id: deviceB.clientId,
        public_key: deviceB.publicKey,
        platform: "linux",
      }),
      approveAll
    )

    const challenge = challengeBodies(vault).at(-1)!
    const registration = vault.requests.find(
      (request) => request.method === "POST" && request.path === "/v1/clients"
    )!
    expect(challenge.method).toBe("POST")
    expect(challenge.path).toBe("/v1/clients")
    expect(challenge.body_sha256).toBe(await sha256Hex(encoder.encode(registration.body!)))
    expect(registration.challengeId).toMatch(/^chl_\d+$/)
    expect(registration.hasProof).toBe(true)
    expect(registration.clientId).toBe(deviceA.clientId)
    // Single use: the row is gone once the bound request succeeds.
    expect(vault.outstandingChallenges()).toBe(0)
  }, 30_000)

  it("uses the empty-body digest for GET and DELETE", async () => {
    const { vault, config } = await registered()
    await vault.register(deviceB)
    await listClients(config)
    await revokeClient(config, deviceB.clientId)

    const bodies = challengeBodies(vault)
    expect(bodies).toEqual([
      { client_id: deviceA.clientId, method: "GET", path: "/v1/clients", body_sha256: EMPTY_BODY_SHA256 },
      {
        client_id: deviceA.clientId,
        method: "DELETE",
        path: `/v1/clients/${deviceB.clientId}`,
        body_sha256: EMPTY_BODY_SHA256,
      },
    ])
    expect(EMPTY_BODY_SHA256).toBe(await sha256Hex(new Uint8Array()))
  }, 30_000)

  it("binds the proof to the organization-prefixed pathname", async () => {
    const { vault, config } = await registered({ account: "org:7", orgPrefix: "example-org" })
    await listClients(config)
    expect(challengeBodies(vault).at(-1)!.path).toBe("/example-org/v1/clients")
  }, 30_000)

  it("fails loudly when the body bytes change between the digest and the request", async () => {
    const { origin, vault, config } = await registered()
    const honest = vault.fetch
    // Re-serializing the JSON with different whitespace is exactly the
    // tampering the digest exists to catch.
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (init?.method === "POST" && url.endsWith("/v1/clients") && init.body) {
        const reserialized = JSON.stringify(JSON.parse(decoder.decode(init.body as Uint8Array)), null, 2)
        return honest(url, { ...init, body: encoder.encode(reserialized) })
      }
      return honest(input, init)
    }) as unknown as typeof fetch

    await expect(
      approveClientEnrollment(
        config,
        encodeEnrollmentRequest({
          version: 1,
          origin,
          account: "user:1",
          client_id: deviceB.clientId,
          public_key: deviceB.publicKey,
          platform: "linux",
        }),
        approveAll
      )
    ).rejects.toThrow("bound to another request body")
    expect(vault.clients.has(deviceB.clientId)).toBe(false)
  }, 30_000)

  it("surfaces the outstanding-challenge limit", async () => {
    const { config } = await registered({ maxOutstandingChallenges: 0 })
    const error = await listClients(config).catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(VaultApiError)
    expect((error as VaultApiError).status).toBe(429)
  }, 30_000)

  it("never puts the account key, private key, or enrollment token in a request body", async () => {
    const { origin, vault, config } = await registered()
    await approveClientEnrollment(
      config,
      encodeEnrollmentRequest({
        version: 1,
        origin,
        account: "user:1",
        client_id: deviceB.clientId,
        public_key: deviceB.publicKey,
        platform: "linux",
      }),
      approveAll
    )
    const bodies = vault.requests.map((request) => request.body ?? "").join("\n")
    expect(bodies).not.toContain(encodeBase64(vault.accountKey))
    expect(bodies).not.toContain(String((deviceA.privateKey as Record<string, string>).d))
    expect(bodies).not.toContain(String((deviceB.privateKey as Record<string, string>).d))
    expect(bodies).not.toContain("private")
  }, 30_000)
})

describe("installation identity on data requests", () => {
  it("sends the installation header on the coordinate lookup, which carries a query string", async () => {
    // Every vlt:// read starts with GET /v1/coordinates?provider=…&owner=…, and
    // the service gates that route on the installation identity. Matching the
    // raw request path instead of its pathname silently dropped the header and
    // turned every user-authenticated vlt:// read into a 403.
    const origin = nextOrigin()
    const vault = createFakeVault({ account: "user:1" })
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA)
    const config: VaultConfig = { baseUrl: origin, token: "caller-token", org: null }
    const seen: { path: string; clientId: string | null }[] = []
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
      const url = new URL(request.url)
      if (url.pathname === "/v1/status") return vault.handle(request)
      seen.push({ path: `${url.pathname}${url.search}`, clientId: request.headers.get("X-CVLT-Client-ID") })
      return Response.json({ status: 500, message: "stop after the coordinate lookup" }, { status: 500 })
    }) as unknown as typeof fetch

    delete process.env.OP_CONNECT_TOKEN
    try {
      await expect(
        handleSecretsApi(config, "/v1/read?ref=vlt%3A%2F%2Fgithub.com%2Fexample-org%2FEXAMPLE_SECRET", async () => null)
      ).rejects.toThrow("stop after the coordinate lookup")
    } finally {
      process.env.OP_CONNECT_TOKEN = "test-connect-token"
    }
    expect(seen).toEqual([
      { path: "/v1/coordinates?provider=github.com&owner=example-org", clientId: deviceA.clientId },
    ])
  }, 30_000)

  it("does not unlock the local key store for an API-key data request", async () => {
    const origin = nextOrigin()
    await saveDeviceKey(origin, deviceA)
    const config: VaultConfig = {
      baseUrl: origin,
      token: "api-key",
      org: null,
      installationIdentity: false,
    }
    let clientId: string | null = "not-called"
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
      clientId = request.headers.get("X-CVLT-Client-ID")
      return Response.json({ status: 500, message: "stop after the coordinate lookup" }, { status: 500 })
    }) as unknown as typeof fetch

    await expect(
      handleSecretsApi(config, "/v1/read?ref=vlt%3A%2F%2Fgithub.com%2Fexample-org%2FEXAMPLE_SECRET", async () => null)
    ).rejects.toThrow("stop after the coordinate lookup")
    expect(clientId).toBeNull()
    expect(loadCalls).toBe(0)
  })

  it("does not send an origin key while the selected account is uninitialized", async () => {
    const origin = nextOrigin()
    await saveDeviceKey(origin, deviceA)
    const vault = createFakeVault({ account: "org:7", orgPrefix: "example-org", initialized: false })
    const config: VaultConfig = {
      baseUrl: `${origin}/example-org`,
      token: "caller-token",
      org: "example-org",
    }
    const clientIds: Array<string | null> = []
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
      if (new URL(request.url).pathname.endsWith("/v1/vaults")) {
        clientIds.push(request.headers.get("X-CVLT-Client-ID"))
        return Response.json([])
      }
      return vault.handle(request)
    }) as unknown as typeof fetch

    expect((await handleApi(config, "/v1/vaults", {}, async () => null)).value).toEqual([])
    expect(clientIds).toEqual([null])
  })

  it("keeps sending the origin key for an initialized but unregistered account", async () => {
    const origin = nextOrigin()
    await saveDeviceKey(origin, deviceA)
    const vault = createFakeVault({ account: "org:7", orgPrefix: "example-org" })
    const config: VaultConfig = {
      baseUrl: `${origin}/example-org`,
      token: "caller-token",
      org: "example-org",
    }
    let clientId: string | null = null
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const request = input instanceof Request && init === undefined ? input : new Request(String(input), init)
      if (new URL(request.url).pathname.endsWith("/v1/vaults")) {
        clientId = request.headers.get("X-CVLT-Client-ID")
        return Response.json({ status: 403, message: "This installation is not registered" }, { status: 403 })
      }
      return vault.handle(request)
    }) as unknown as typeof fetch

    await expect(handleApi(config, "/v1/vaults", {}, async () => null)).rejects.toThrow(
      "This installation is not registered"
    )
    expect(clientId).toBe(deviceA.clientId)
  })
})

describe("listing and revocation", () => {
  it("identifies the current installation and returns no key material", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA, { name: "approver" })
    await vault.register(deviceB, { name: "example-workstation", platform: "linux" })

    const clients = await listClients(config)
    expect(clients).toEqual([
      { id: deviceA.clientId, name: "approver", platform: "darwin", created_at: "2026-08-23T00:00:00.000Z", is_current: true },
      { id: deviceB.clientId, name: "example-workstation", platform: "linux", created_at: "2026-08-23T00:00:00.000Z", is_current: false },
    ])
    const serialized = JSON.stringify(clients)
    expect(serialized).not.toContain("public_key")
    expect(serialized).not.toContain("wrapped")
    expect(serialized).not.toContain((deviceA.publicKey as { n: string }).n)
  }, 30_000)

  it("revokes another installation and leaves the caller readable", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA)
    await vault.register(deviceB)

    const result = await revokeClient(config, deviceB.clientId)
    expect(result).toEqual({ client_id: deviceB.clientId, account: "user:1", origin })
    expect(vault.clients.get(deviceB.clientId)!.revoked).toBe(true)
    expect(vault.clients.get(deviceA.clientId)!.revoked).toBe(false)
    resetE2eeCaches()
    expect(await listClients(config)).toEqual([
      expect.objectContaining({ id: deviceA.clientId, is_current: true }),
    ])
  }, 30_000)

  it("refuses to revoke the current installation", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA)
    await expect(revokeClient(config, deviceA.clientId)).rejects.toThrow("from itself is not allowed")
    expect(vault.clients.get(deviceA.clientId)!.revoked).toBe(false)
    expect(vault.requests.some((request) => request.method === "DELETE")).toBe(false)
  }, 30_000)

  it("reports the existing not-registered failure once revoked", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceB)
    await vault.register(deviceB, { revoked: true })
    await expect(listClients(config)).rejects.toThrow("This installation is not registered")
    resetE2eeCaches()
    await expect(revokeClient(config, deviceA.clientId)).rejects.toThrow("This installation is not registered")
  }, 30_000)

  it("reports a 404 for an unknown target", async () => {
    const { origin, vault, config } = deploy()
    await saveDeviceKey(origin, deviceA)
    await vault.register(deviceA)
    const error = await revokeClient(config, deviceB.clientId).catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(VaultApiError)
    expect((error as VaultApiError).status).toBe(404)
  }, 30_000)
})
