import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test"
import { handleApi, handleSecretsApi, resetE2eeCaches } from "./e2ee-client"
import { encodeBase64, encryptJson, itemLocator, randomKey } from "./e2ee-crypto"

const vaultId = "01j00000000000000000000001"
const itemId = "01j00000000000000000000002"
const realFetch = globalThis.fetch
const originalOidcUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL
const originalOidcToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
const originalConnectToken = process.env.OP_CONNECT_TOKEN

beforeEach(() => {
  resetE2eeCaches()
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://github.example/oidc"
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "request-token"
  delete process.env.OP_CONNECT_TOKEN
})

afterEach(() => {
  globalThis.fetch = realFetch
  resetE2eeCaches()
  if (originalOidcUrl === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  else process.env.ACTIONS_ID_TOKEN_REQUEST_URL = originalOidcUrl
  if (originalOidcToken === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  else process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = originalOidcToken
  if (originalConnectToken === undefined) delete process.env.OP_CONNECT_TOKEN
  else process.env.OP_CONNECT_TOKEN = originalConnectToken
})

describe("E2EE request cache", () => {
  it("deduplicates raw rows and resolves titles without sending plaintext", async () => {
    const key = randomKey()
    const vaultRow = {
      id: vaultId,
      attribute_version: 1,
      content_version: 1,
      created_at: "2026-08-03T00:00:00Z",
      updated_at: "2026-08-03T00:00:00Z",
      items: 1,
      format_version: 1,
      overview: await encryptJson(
        { name: "Production", description: "", type: "USER_CREATED" },
        key,
        `cvlt:v1:vault:${vaultId}:overview`
      ),
      wrapped_vault_key: null,
      kms_wrapped_vault_key: {
        version: 1,
        algorithm: "RSA-OAEP-3072-SHA256",
        ciphertext: "wrapped",
      },
      coordinate: null,
    }
    const itemRow = {
      id: itemId,
      vault_id: vaultId,
      version: 1,
      created_at: "2026-08-03T00:00:00Z",
      updated_at: "2026-08-03T00:00:00Z",
      format_version: 1,
      locator: await itemLocator(key, "Database"),
      overview: await encryptJson(
        { title: "Database", category: "LOGIN", tags: [], favorite: false, urls: [] },
        key,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:overview`
      ),
      details: await encryptJson(
        { fields: [{ id: "password", value: "secret" }], sections: [], password_history: [] },
        key,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:details`
      ),
    }
    const requests: { url: string; method: string; body?: string }[] = []
    globalThis.fetch = mock(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? "GET"
      const body = typeof init?.body === "string" ? init.body : undefined
      requests.push({ url, method, ...(body === undefined ? {} : { body }) })
      if (url === "https://vault.example/v1/status") {
        return Response.json({
          account: "user:1",
          initialized: true,
          format_version: 1,
          client: null,
          kms: {
            public_key_pem: null,
            wif_audience: "kms-audience",
            key_version: "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
          },
        })
      }
      if (url === "https://vault.example/v1/vaults") return Response.json([vaultRow])
      if (url === "https://sts.googleapis.com/v1/token") return Response.json({ access_token: "gcp-token" })
      if (url.startsWith("https://cloudkms.googleapis.com/v1/")) {
        return Response.json({
          plaintext: Buffer.from(JSON.stringify({
            version: 1,
            vault_id: vaultId,
            vault_key: encodeBase64(key),
          })).toString("base64"),
        })
      }
      if (url === `https://vault.example/v1/vaults/${vaultId}/items/resolve`) {
        return Response.json(itemRow)
      }
      return Response.json({ status: 404, message: "unexpected request" }, { status: 404 })
    }) as unknown as typeof fetch

    const config = { baseUrl: "https://vault.example", token: "caller", org: null }
    const fetchOidcToken = async () => "subject-token"
    const [firstVaults, secondVaults] = await Promise.all([
      handleApi<Record<string, unknown>[]>(config, "/v1/vaults", {}, fetchOidcToken),
      handleApi<Record<string, unknown>[]>(config, "/v1/vaults", {}, fetchOidcToken),
    ])
    expect(firstVaults.value).toEqual(secondVaults.value)

    const resolved = await handleApi<Record<string, unknown>>(
      config,
      `/v1/vaults/${vaultId}/items/resolve`,
      { method: "POST", body: { title: "Database" } },
      fetchOidcToken
    )
    expect(resolved.value).toMatchObject({ id: itemId, title: "Database" })

    const item = await handleApi<Record<string, unknown>>(
      config,
      `/v1/vaults/${vaultId}/items/${itemId}`,
      {},
      fetchOidcToken
    )
    expect(item.value).toMatchObject({ id: itemId, title: "Database" })

    expect(requests.filter((request) => request.url.endsWith("/v1/status"))).toHaveLength(1)
    expect(requests.filter((request) => request.url.startsWith("https://vault.example/"))).toHaveLength(3)
    expect(requests.filter((request) => request.url === "https://vault.example/v1/vaults")).toHaveLength(1)
    expect(requests.filter((request) => request.url === `https://vault.example/v1/vaults/${vaultId}`)).toHaveLength(0)
    expect(requests.filter((request) => request.url.endsWith(`/items/${itemId}`))).toHaveLength(0)
    expect(requests.filter((request) => request.url === "https://sts.googleapis.com/v1/token")).toHaveLength(1)
    expect(requests.filter((request) => request.url.startsWith("https://cloudkms.googleapis.com/v1/"))).toHaveLength(1)
    const resolveRequest = requests.find((request) => request.url.endsWith("/items/resolve"))!
    expect(JSON.parse(resolveRequest.body!)).toEqual({ locator: itemRow.locator })
    expect(resolveRequest.body).not.toContain("Database")
  })
})

describe("mixed plain content", () => {
  it("lists and reveals a plain integration item without local E2EE state", async () => {
    const requests: string[] = []
    globalThis.fetch = mock(async (input: string | URL | Request) => {
      const url = String(input)
      requests.push(url)
      if (url === "https://vault.example/v1/vaults") {
        return Response.json([{
          id: vaultId,
          name: "prism-dev.circles.ac",
          type: "SERVICE_MANAGED",
          content_mode: "plain",
          integration_coordinate: "prism-dev.circles.ac",
          attribute_version: 1,
          content_version: 1,
          items: 1,
          created_at: "2026-08-06T00:00:00Z",
          updated_at: "2026-08-06T00:00:00Z",
          kms_wrapped_vault_key: null,
        }])
      }
      if (url === `https://vault.example/v1/vaults/${vaultId}/items`) {
        return Response.json([{
          id: itemId,
          vault_id: vaultId,
          version: 1,
          content_mode: "plain",
          title: "ChatGPT — person@example.com",
          category: "API_CREDENTIAL",
          tags: ["prism", "provider:chatgpt", "account:account-1"],
          created_at: "2026-08-06T00:00:00Z",
          updated_at: "2026-08-06T00:00:00Z",
        }])
      }
      if (url === `https://vault.example/v1/vaults/${vaultId}/items/${itemId}`) {
        return Response.json({
          id: itemId,
          vault_id: vaultId,
          version: 1,
          content_mode: "plain",
          title: "ChatGPT — person@example.com",
          category: "API_CREDENTIAL",
          fields: [{ id: "credential", value: "secret" }],
          created_at: "2026-08-06T00:00:00Z",
          updated_at: "2026-08-06T00:00:00Z",
        })
      }
      return Response.json({ status: 404 }, { status: 404 })
    }) as unknown as typeof fetch

    const config = { baseUrl: "https://vault.example", token: "caller", org: null }
    const vaults = await handleApi<Record<string, unknown>[]>(config, "/v1/vaults", {}, async () => null)
    expect(vaults.value).toEqual([expect.objectContaining({ name: "prism-dev.circles.ac" })])
    const items = await handleApi<Record<string, unknown>[]>(
      config,
      `/v1/vaults/${vaultId}/items`,
      {},
      async () => null
    )
    expect(items.value).toEqual([expect.objectContaining({ title: "ChatGPT — person@example.com" })])
    const item = await handleApi<Record<string, unknown>>(
      config,
      `/v1/vaults/${vaultId}/items/${itemId}`,
      {},
      async () => null
    )
    expect(item.value).toMatchObject({ fields: [{ id: "credential", value: "secret" }] })
    expect(requests.some((url) => url.endsWith("/v1/status"))).toBe(false)
  })
})

describe("mixed owner-global coordinate reads", () => {
  it("resolves a service-managed plain item without changing E2EE inheritance order", async () => {
    const key = randomKey()
    const vaultRow = {
      id: vaultId,
      attribute_version: 1,
      content_version: 2,
      created_at: "2026-08-21T00:00:00Z",
      updated_at: "2026-08-21T00:00:00Z",
      items: 2,
      format_version: 1,
      overview: await encryptJson(
        { name: "github.com/circlesac", description: "", type: "USER_CREATED" },
        key,
        `cvlt:v1:vault:${vaultId}:overview`
      ),
      wrapped_vault_key: null,
      kms_wrapped_vault_key: {
        version: 1,
        algorithm: "RSA-OAEP-3072-SHA256",
        ciphertext: "wrapped",
      },
      coordinate: { provider: "github.com", owner: "circlesac", repository: null },
    }
    const plainSummary = {
      id: itemId,
      vault_id: vaultId,
      version: 1,
      content_mode: "plain",
      title: "LINUX_RUNNER",
      category: "runner-routing",
      created_at: "2026-08-21T00:00:00Z",
      updated_at: "2026-08-21T00:00:00Z",
    }
    let coordinateBody: Record<string, unknown> | undefined
    globalThis.fetch = mock(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url === "https://vault.example/v1/status") {
        return Response.json({
          account: "org:circlesac",
          initialized: true,
          format_version: 1,
          client: null,
          kms: {
            public_key_pem: null,
            wif_audience: "kms-audience",
            key_version: "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
          },
        })
      }
      if (url === "https://vault.example/v1/coordinates?provider=github.com&owner=circlesac") {
        return Response.json([vaultRow])
      }
      if (url === `https://vault.example/v1/vaults/${vaultId}/items`) return Response.json([plainSummary])
      if (url === "https://sts.googleapis.com/v1/token") return Response.json({ access_token: "gcp-token" })
      if (url.startsWith("https://cloudkms.googleapis.com/v1/")) {
        return Response.json({
          plaintext: Buffer.from(JSON.stringify({
            version: 1,
            vault_id: vaultId,
            vault_key: encodeBase64(key),
          })).toString("base64"),
        })
      }
      if (url === "https://vault.example/v1/coordinates/read") {
        coordinateBody = JSON.parse(String(init?.body)) as Record<string, unknown>
        return Response.json({
          ...plainSummary,
          fields: [{ id: "value", label: "value", value: JSON.stringify(["self-hosted", "ubuntu-latest"]) }],
          sections: [],
        })
      }
      return Response.json({ status: 404, message: "unexpected request" }, { status: 404 })
    }) as unknown as typeof fetch

    const result = await handleSecretsApi<{ value: string }>(
      { baseUrl: "https://vault.example", token: "caller", org: "circlesac" },
      "/v1/read?ref=vlt%3A%2F%2Fgithub.com%2Fcirclesac%2FLINUX_RUNNER",
      async () => "subject-token"
    )

    expect(result).toEqual({ handled: true, value: { value: JSON.stringify(["self-hosted", "ubuntu-latest"]) } })
    const candidates = coordinateBody?.candidates as Array<Record<string, unknown>>
    expect(candidates).toHaveLength(2)
    expect(candidates[0]).toEqual({ vault_id: vaultId, locator: await itemLocator(key, "LINUX_RUNNER") })
    expect(candidates[1]).toEqual({ vault_id: vaultId, item_id: itemId })
    expect(JSON.stringify(coordinateBody)).not.toContain('"title"')
    expect(JSON.stringify(coordinateBody)).not.toContain("LINUX_RUNNER")
  })
})
