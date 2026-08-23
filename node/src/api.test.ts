/**
 * Unit tests for the OIDC client helpers in api.ts.
 * Uses bun's built-in test runner — no extra deps.
 *
 * Run: bun test
 */

import { describe, it, expect, beforeEach, afterEach, mock } from "bun:test"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  _resetOidcCache,
  fetchGithubOidcToken,
  getCirclesToken,
  getConfig,
  getConfigForVltOwner,
  hasGithubOidcEnv,
  resolveItem,
  resolveVault,
  setOverrides,
} from "./api"

// Build a minimal valid JWT structure (header.payload.signature) so callers
// that try to parse `exp` from the payload succeed.
function fakeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" }))
    .toString("base64url")
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url")
  return `${header}.${payload}.sig`
}

const realFetch = globalThis.fetch
let fetchSpy: ReturnType<typeof mock>

beforeEach(() => {
  _resetOidcCache()
  fetchSpy = mock(async () => new Response(null, { status: 200 }))
  globalThis.fetch = fetchSpy as unknown as typeof fetch
})

afterEach(() => {
  globalThis.fetch = realFetch
})

describe("hasGithubOidcEnv", () => {
  it("returns true when both vars are present", () => {
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://example/token?token=x",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "abc",
      } as NodeJS.ProcessEnv)
    ).toBe(true)
  })

  it("returns false when either var is missing", () => {
    expect(hasGithubOidcEnv({} as NodeJS.ProcessEnv)).toBe(false)
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_URL: "x",
      } as NodeJS.ProcessEnv)
    ).toBe(false)
    expect(
      hasGithubOidcEnv({
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "abc",
      } as NodeJS.ProcessEnv)
    ).toBe(false)
  })
})

describe("opaque ID resolution", () => {
  it("does not make lookup requests for vault and item IDs", async () => {
    const vaultId = "01j00000000000000000000001"
    const itemId = "01j00000000000000000000002"
    expect(await resolveVault(vaultId)).toBe(vaultId)
    expect(await resolveItem(vaultId, itemId)).toBe(itemId)
    expect(fetchSpy.mock.calls).toHaveLength(0)
  })
})

describe("fetchGithubOidcToken", () => {
  it("returns null when OIDC env vars are missing", async () => {
    const tok = await fetchGithubOidcToken("aud", {} as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
    expect(fetchSpy.mock.calls.length).toBe(0)
  })

  it("appends audience to the request URL and uses request token as Bearer", async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600
    const fakeToken = fakeJwt(futureExp)
    fetchSpy = mock(async () => new Response(JSON.stringify({ value: fakeToken }), { status: 200 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const aud = "https://vault.circles.ac/circlesac"
    const tok = await fetchGithubOidcToken(aud, {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token?token=x",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    } as NodeJS.ProcessEnv)
    expect(tok).toBe(fakeToken)
    expect(fetchSpy.mock.calls.length).toBe(1)
    const [calledUrl, init] = fetchSpy.mock.calls[0]!
    expect(calledUrl).toBe(`https://gh.example/token?token=x&audience=${encodeURIComponent(aud)}`)
    expect((init as RequestInit).headers).toEqual({ Authorization: "Bearer request-token" })
  })

  it("appends ? when the request URL has no existing query string", async () => {
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ value: fakeJwt(Math.floor(Date.now() / 1000) + 3600) }))
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(fetchSpy.mock.calls[0]![0]).toBe("https://gh.example/token?audience=aud")
  })

  it("returns null on non-OK response", async () => {
    fetchSpy = mock(async () => new Response("Forbidden", { status: 403 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })

  it("returns null when response has no value field", async () => {
    fetchSpy = mock(async () => new Response(JSON.stringify({}), { status: 200 }))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })

  it("caches the token for the same audience until near expiry", async () => {
    const fakeToken = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    fetchSpy = mock(async () => new Response(JSON.stringify({ value: fakeToken })))
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const env = {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv

    const a = await fetchGithubOidcToken("aud-1", env)
    const b = await fetchGithubOidcToken("aud-1", env)
    expect(a).toBe(fakeToken)
    expect(b).toBe(fakeToken)
    // Single network call thanks to the cache
    expect(fetchSpy.mock.calls.length).toBe(1)
  })

  it("re-fetches when the audience changes", async () => {
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ value: fakeJwt(Math.floor(Date.now() / 1000) + 3600) }))
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const env = {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv
    await fetchGithubOidcToken("aud-A", env)
    await fetchGithubOidcToken("aud-B", env)
    expect(fetchSpy.mock.calls.length).toBe(2)
  })

  it("returns null when fetch throws", async () => {
    fetchSpy = mock(async () => {
      throw new Error("network down")
    })
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    const tok = await fetchGithubOidcToken("aud", {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://gh.example/token",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
    } as NodeJS.ProcessEnv)
    expect(tok).toBeNull()
  })
})

describe("getConfig shared Circles credentials", () => {
  const envKeys = [
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "CIRCLES_AUTH_TOKEN",
    "CIRCLES_CONFIG_FILE",
    "CIRCLES_PROFILE",
    "CIRCLES_SHARED_CREDENTIALS_FILE",
    "CRCL_AUTH_TOKEN",
    "CRCL_ORG",
    "CRCL_PROFILE",
    "OP_CONNECT_AUDIENCE",
    "OP_CONNECT_HOST",
    "OP_CONNECT_TOKEN",
    "PATH",
  ] as const
  const originalEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]))
  let tempDir = ""
  let configFile = ""
  let credentialsFile = ""

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "cvlt-credentials-"))
    configFile = join(tempDir, "config")
    credentialsFile = join(tempDir, "credentials")
    for (const key of envKeys) delete process.env[key]
    process.env.CIRCLES_CONFIG_FILE = configFile
    process.env.CIRCLES_SHARED_CREDENTIALS_FILE = credentialsFile
    setOverrides({})
  })

  afterEach(() => {
    setOverrides({})
    rmSync(tempDir, { recursive: true, force: true })
    for (const key of envKeys) {
      const value = originalEnv[key]
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  })

  it("distinguishes an opaque API key from a manual user JWT", async () => {
    process.env.OP_CONNECT_HOST = "https://vault.circles.ac/example-org"
    process.env.OP_CONNECT_TOKEN = "opaque-api-key"
    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.circles.ac/example-org",
      token: "opaque-api-key",
      org: "example-org",
      installationIdentity: false,
    })

    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.OP_CONNECT_TOKEN = token
    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.circles.ac/example-org",
      token,
      org: "example-org",
      installationIdentity: true,
    })
  })

  it("uses the shared current profile and its development endpoints", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    writeFileSync(configFile, [
      "[__circles__]",
      "current_profile = dev:user@example.com",
      "",
      "[dev:user@example.com]",
      "api_url = https://api-dev.circles.ac",
      "auth_url = https://auth-dev.circles.ac",
      "org = must-not-auto-escalate",
      "",
    ].join("\n"))
    writeFileSync(credentialsFile, [
      "[dev:user@example.com]",
      `access_token = ${token}`,
      "",
    ].join("\n"))
    process.env.PATH = ""

    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.crcl.es",
      token,
      org: null,
    })
  })

  it("keeps an explicit profile ahead of an environment credential", async () => {
    const profileToken = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = fakeJwt(Math.floor(Date.now() / 1000) + 7200)
    writeFileSync(configFile, [
      "[dev:user@example.com]",
      "api_url = https://api-dev.circles.ac",
      "auth_url = https://auth-dev.circles.ac",
      "",
    ].join("\n"))
    writeFileSync(credentialsFile, [
      "[dev:user@example.com]",
      `access_token = ${profileToken}`,
      "",
    ].join("\n"))
    setOverrides({ profile: "dev:user@example.com" })

    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.crcl.es",
      token: profileToken,
      org: null,
    })
    expect(await getCirclesToken()).toBe(profileToken)
  })

  it("supports a headless canonical environment credential without files", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token

    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.circles.ac",
      token,
      org: null,
    })
  })

  it("infers an accessible org from a vlt owner and caches the probe", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    fetchSpy = mock(async (url) => {
      expect(url).toBe("https://vault.circles.ac/circlesac/v1/status")
      return new Response("[]")
    })
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    expect(await getConfigForVltOwner("CirclesAC")).toEqual({
      baseUrl: "https://vault.circles.ac/circlesac",
      token,
      org: "circlesac",
    })
    expect(await getConfigForVltOwner("circlesac")).toEqual({
      baseUrl: "https://vault.circles.ac/circlesac",
      token,
      org: "circlesac",
    })
    expect(fetchSpy.mock.calls).toHaveLength(1)
  })

  it("resolves mixed vlt owners independently", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    fetchSpy = mock(async (url) => {
      if (url === "https://vault.circles.ac/circlesac/v1/status") {
        return new Response("[]")
      }
      return new Response(JSON.stringify({ message: "Org not found" }), { status: 403 })
    })
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const [organization, personal] = await Promise.all([
      getConfigForVltOwner("circlesac"),
      getConfigForVltOwner("personal-owner"),
    ])
    expect(organization.org).toBe("circlesac")
    expect(personal.org).toBeNull()
    expect(fetchSpy.mock.calls).toHaveLength(2)
  })

  it("keeps the personal account when the vlt owner is not an accessible org", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ message: "Not a member of this organization" }), { status: 403 })
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    expect(await getConfigForVltOwner("personal-owner")).toEqual({
      baseUrl: "https://vault.circles.ac",
      token,
      org: null,
    })
  })

  it("does not hide other org authorization failures behind personal fallback", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    fetchSpy = mock(async () =>
      new Response(JSON.stringify({ message: "Access restricted" }), { status: 403 })
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    await expect(getConfigForVltOwner("circlesac")).rejects.toMatchObject({
      status: 403,
      message: "Access restricted",
    })
  })

  it("rejects an explicit org that differs from the vlt owner", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    setOverrides({ org: "melten" })

    await expect(getConfigForVltOwner("circlesac")).rejects.toThrow(
      "vlt:// owner 'circlesac' does not match selected org 'melten'"
    )
    expect(fetchSpy.mock.calls).toHaveLength(0)
  })

  it("uses a matching explicit org without probing", async () => {
    const token = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    process.env.CIRCLES_AUTH_TOKEN = token
    setOverrides({ org: "circlesac" })

    expect(await getConfigForVltOwner("circlesac")).toEqual({
      baseUrl: "https://vault.circles.ac/circlesac",
      token,
      org: "circlesac",
    })
    expect(fetchSpy.mock.calls).toHaveLength(0)
  })

  it("refreshes an expired profile directly without the crcl executable", async () => {
    const expiredToken = fakeJwt(Math.floor(Date.now() / 1000) - 60)
    const freshToken = fakeJwt(Math.floor(Date.now() / 1000) + 3600)
    writeFileSync(configFile, [
      "[__circles__]",
      "current_profile = prod:user@example.com",
      "",
      "[prod:user@example.com]",
      "api_url = https://api.circles.ac",
      "auth_url = https://auth.circles.ac",
      "",
    ].join("\n"))
    writeFileSync(credentialsFile, [
      "[prod:user@example.com]",
      `access_token = ${expiredToken}`,
      "refresh_token = refresh-old",
      "",
    ].join("\n"))
    process.env.PATH = ""
    fetchSpy = mock(async () => new Response(JSON.stringify({
      access_token: freshToken,
      refresh_token: "refresh-new",
    })))
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    expect(await getConfig()).toEqual({
      baseUrl: "https://vault.circles.ac",
      token: freshToken,
      org: null,
    })
    expect(fetchSpy.mock.calls[0]![0]).toBe("https://auth.circles.ac/token")
    expect(readFileSync(credentialsFile, "utf8")).toContain("refresh_token = refresh-new")
    expect(readFileSync(credentialsFile, "utf8")).not.toContain("refresh_token = refresh-old")
  })
})
