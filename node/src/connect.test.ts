import { beforeEach, describe, expect, it } from "bun:test"
import { unlink } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createConnectClient } from "./connect"
import { decryptJson, encryptJson, randomKey, type RsaEnvelope } from "./e2ee-crypto"

const vaultId = "01j00000000000000000000001"
const itemId = "01j00000000000000000000002"
const wrappedVaultKey: RsaEnvelope = {
  version: 1,
  algorithm: "RSA-OAEP-3072-SHA256",
  ciphertext: "wrapped",
}

describe("Connect-compatible E2EE client", () => {
  let vaultKey: Uint8Array
  let vaultRow: Record<string, unknown>
  let itemRow: Record<string, unknown>
  let upstreamRequests: Request[]

  beforeEach(async () => {
    vaultKey = randomKey()
    upstreamRequests = []
    vaultRow = {
      id: vaultId,
      attribute_version: 1,
      content_version: 1,
      created_at: "2026-08-02T00:00:00Z",
      updated_at: "2026-08-02T00:00:00Z",
      items: 1,
      format_version: 1,
      overview: await encryptJson(
        { name: "Production", description: "", type: "USER_CREATED" },
        vaultKey,
        `cvlt:v1:vault:${vaultId}:overview`
      ),
      wrapped_vault_key: null,
      kms_wrapped_vault_key: wrappedVaultKey,
    }
    itemRow = {
      id: itemId,
      vault_id: vaultId,
      version: 7,
      created_at: "2026-08-02T00:00:00Z",
      updated_at: "2026-08-02T00:00:00Z",
      format_version: 1,
      locator: "locator",
      overview: await encryptJson(
        {
          title: "Database",
          category: "LOGIN",
          tags: ["production"],
          favorite: false,
          urls: [],
        },
        vaultKey,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:overview`
      ),
      details: await encryptJson(
        {
          fields: [{ id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD", value: "old-value" }],
          sections: [],
          password_history: [],
        },
        vaultKey,
        `cvlt:v1:vault:${vaultId}:item:${itemId}:details`
      ),
    }
  })

  function client() {
    const fetcher = {
      async fetch(input: Request | string | URL) {
        const request = input instanceof Request ? input : new Request(input)
        upstreamRequests.push(request.clone())
        const path = new URL(request.url).pathname
        if (path === "/v1/status") return Response.json({ kms: { key_version: "projects/test/keyVersions/1" } })
        if (path === "/v1/vaults") return Response.json([vaultRow])
        if (path === `/v1/vaults/${vaultId}`) return Response.json(vaultRow)
        if (path === `/v1/vaults/${vaultId}/items`) return Response.json([itemRow])
        if (path === `/v1/vaults/${vaultId}/items/${itemId}` && request.method === "GET") {
          return Response.json(itemRow)
        }
        if (path === `/v1/vaults/${vaultId}/items/${itemId}` && request.method === "PUT") {
          const body = await request.json<Record<string, unknown>>()
          itemRow = { ...itemRow, ...body, version: 8 }
          return Response.json(itemRow)
        }
        return Response.json({ status: 404 }, { status: 404 })
      },
    }
    return createConnectClient({
      fetcher,
      baseUrl: "https://vault.example.com",
      unwrapVaultKey: async ({ vaultId: requestedVaultId, wrappedVaultKey: wrapped, keyVersion }) => {
        expect(requestedVaultId).toBe(vaultId)
        expect(wrapped).toEqual(wrappedVaultKey)
        expect(keyVersion).toBe("projects/test/keyVersions/1")
        return vaultKey
      },
    })
  }

  it("keeps v1 vault and item responses plaintext-compatible", async () => {
    const connect = client()
    const vaults = await connect.fetch(new Request("https://local/v1/vaults?filter=title%20eq%20%22Production%22", {
      headers: { Authorization: "Bearer caller", "X-CVLT-Client-ID": "example-client-id" },
    }))
    expect(vaults.status).toBe(200)
    expect(await vaults.json()).toEqual([expect.objectContaining({ id: vaultId, name: "Production" })])

    const items = await connect.fetch(new Request(`https://local/v1/vaults/${vaultId}/items?tags=production`, {
      headers: { Authorization: "Bearer caller" },
    }))
    expect(items.status).toBe(200)
    expect(await items.json()).toEqual([expect.objectContaining({ id: itemId, title: "Database" })])

    const item = await connect.fetch(new Request(`https://local/v1/vaults/${vaultId}/items/${itemId}`, {
      headers: { Authorization: "Bearer caller" },
    }))
    expect(item.headers.get("ETag")).toBe('"7"')
    expect(await item.json()).toMatchObject({
      title: "Database",
      fields: [{ id: "password", value: "old-value" }],
    })
    expect(upstreamRequests.every((request) => request.headers.get("Authorization") === "Bearer caller")).toBe(true)
    expect(upstreamRequests[0]!.headers.get("X-CVLT-Client-ID")).toBe("example-client-id")
  })

  it.skipIf(!Bun.which("op"))("supports op read, inject, and run", async () => {
    const connect = client()
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        if (request.headers.get("Authorization") !== "Bearer fixture-token") {
          return Response.json({ status: 401, message: "Invalid Connect token" }, { status: 401 })
        }
        return connect.fetch(request)
      },
    })
    const env = {
      ...process.env,
      OP_CONNECT_HOST: `http://127.0.0.1:${server.port}`,
      OP_CONNECT_TOKEN: "fixture-token",
    }

    async function runOp(args: string[], extraEnv: Record<string, string> = {}) {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 10_000)
      const subprocess = Bun.spawn([Bun.which("op")!, ...args], {
        env: { ...env, ...extraEnv },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        signal: controller.signal,
      })
      const [exitCode, stdout, stderr] = await Promise.all([
        subprocess.exited,
        new Response(subprocess.stdout).text(),
        new Response(subprocess.stderr).text(),
      ])
      clearTimeout(timeout)
      if (exitCode !== 0) throw new Error(`op ${args[0]} failed (${exitCode}): ${stderr}`)
      return stdout
    }

    try {
      expect(await runOp(["read", "op://Production/Database/password"])).toBe("old-value\n")
      const templatePath = join(tmpdir(), `cvlt-op-${crypto.randomUUID()}.tpl`)
      await Bun.write(templatePath, "password={{ op://Production/Database/password }}")
      try {
        expect(await runOp(["inject", "--in-file", templatePath])).toBe("password=old-value\n")
      } finally {
        await unlink(templatePath)
      }
      expect(await runOp(
        ["run", "--no-masking", "--", process.execPath, "-e", "process.stdout.write(process.env.CVLT_OP_VALUE || '')"],
        { CVLT_OP_VALUE: "op://Production/Database/password" }
      )).toBe("old-value")
    } finally {
      server.stop(true)
    }
  })

  it("encrypts v1 updates and preserves optimistic concurrency", async () => {
    const connect = client()
    const update = await connect.fetch(new Request(`https://local/v1/vaults/${vaultId}/items/${itemId}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer caller",
        "Content-Type": "application/json",
        "If-Match": "7",
      },
      body: JSON.stringify({
        title: "Database",
        category: "LOGIN",
        fields: [{ id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD", value: "new-value" }],
      }),
    }))
    expect(update.status).toBe(200)
    expect(update.headers.get("ETag")).toBe('"8"')
    expect(await update.json()).toMatchObject({ fields: [{ id: "password", value: "new-value" }] })

    const rawUpdate = upstreamRequests.find((request) => request.method === "PUT")!
    const rawBody = await rawUpdate.json<{
      version: number
      overview: Parameters<typeof decryptJson>[0]
      details: Parameters<typeof decryptJson>[0]
    }>()
    expect(rawBody.version).toBe(7)
    expect(JSON.stringify(rawBody)).not.toContain("new-value")
    expect(await decryptJson<Record<string, unknown>>(
      rawBody.details,
      vaultKey,
      `cvlt:v1:vault:${vaultId}:item:${itemId}:details`
    )).toMatchObject({ fields: [{ value: "new-value" }] })

    const stale = await connect.fetch(new Request(`https://local/v1/vaults/${vaultId}/items/${itemId}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer caller",
        "Content-Type": "application/json",
        "If-Match": "7",
      },
      body: JSON.stringify({ title: "stale" }),
    }))
    expect(stale.status).toBe(412)
    expect(upstreamRequests.filter((request) => request.method === "PUT")).toHaveLength(1)
  })

  it("passes plain integration vaults and items through without a Vault key", async () => {
    let unwrapCalls = 0
    const plainVault = {
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
    }
    const plainItem = {
      id: itemId,
      vault_id: vaultId,
      version: 1,
      content_mode: "plain",
      title: "ChatGPT — person@example.com",
      category: "API_CREDENTIAL",
      tags: ["prism", "provider:chatgpt", "account:account-1"],
      fields: [{ id: "credential", value: "secret" }],
      created_at: "2026-08-06T00:00:00Z",
      updated_at: "2026-08-06T00:00:00Z",
    }
    const fetcher = {
      async fetch(input: Request | string | URL) {
        const request = input instanceof Request ? input : new Request(input)
        const path = new URL(request.url).pathname
        if (path === "/v1/vaults") return Response.json([plainVault])
        if (path === `/v1/vaults/${vaultId}`) return Response.json(plainVault)
        if (path === `/v1/vaults/${vaultId}/items`) {
          return Response.json([{ ...plainItem, fields: undefined }])
        }
        if (path === `/v1/vaults/${vaultId}/items/${itemId}`) return Response.json(plainItem)
        return Response.json({ status: 404 }, { status: 404 })
      },
    }
    const connect = createConnectClient({
      fetcher,
      unwrapVaultKey: async () => {
        unwrapCalls++
        throw new Error("plain content must not unwrap a key")
      },
    })

    expect(await (await connect.fetch("https://local/v1/vaults")).json()).toEqual([
      expect.objectContaining({ name: "prism-dev.circles.ac", content_mode: "plain" }),
    ])
    expect(await (await connect.fetch(`https://local/v1/vaults/${vaultId}/items`)).json()).toEqual([
      expect.objectContaining({ id: itemId, title: "ChatGPT — person@example.com" }),
    ])
    expect(await (await connect.fetch(`https://local/v1/vaults/${vaultId}/items/${itemId}`)).json()).toMatchObject({
      fields: [{ id: "credential", value: "secret" }],
    })
    expect(unwrapCalls).toBe(0)
  })
})
