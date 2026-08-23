import { describe, expect, it } from "bun:test"
import {
  assertPublicJwk,
  canonicalEnrollmentJson,
  decodeEnrollmentRequest,
  encodeEnrollmentRequest,
  formatFingerprint,
  normalizeClientName,
  normalizeVaultOrigin,
  type EnrollmentRequest,
} from "./client-enrollment"
import {
  canonicalPublicJwk,
  decodeBase64,
  encodeBase64,
  generateDeviceKey,
  publicKeyFingerprint,
} from "./e2ee-crypto"

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const device = await generateDeviceKey()

function baseRequest(overrides: Partial<EnrollmentRequest> = {}): EnrollmentRequest {
  return {
    version: 1,
    origin: "https://vault.example",
    account: "user:1",
    client_id: device.clientId,
    public_key: device.publicKey,
    platform: "linux",
    ...overrides,
  }
}

function tokenOf(value: unknown): string {
  return encodeBase64(encoder.encode(JSON.stringify(value)))
}

function decodedJson(token: string): Record<string, unknown> {
  return JSON.parse(decoder.decode(decodeBase64(token))) as Record<string, unknown>
}

describe("device key fingerprint", () => {
  it("derives the client ID from the canonical public JWK", async () => {
    expect(await publicKeyFingerprint(device.publicKey)).toBe(device.clientId)
    expect(device.clientId).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it("is independent of the property order a runtime exports", async () => {
    const shuffled = Object.fromEntries(
      Object.entries(device.publicKey as Record<string, unknown>).reverse()
    ) as JsonWebKey
    expect(Object.keys(shuffled)).not.toEqual(Object.keys(device.publicKey as object))
    expect(await publicKeyFingerprint(shuffled)).toBe(device.clientId)
    expect(canonicalPublicJwk(shuffled)).toEqual(canonicalPublicJwk(device.publicKey))
  })

  it("does not expose the private key through the stored public JWK", () => {
    expect(Object.keys(device.publicKey as object).sort()).toEqual(["alg", "e", "ext", "key_ops", "kty", "n"])
    expect(JSON.stringify(device.publicKey)).not.toContain(String((device.privateKey as { d: string }).d))
  })
})

describe("enrollment request encoding", () => {
  it("round-trips and re-encodes to the identical token", async () => {
    const token = encodeEnrollmentRequest(baseRequest({ name: "example-workstation" }))
    const decoded = await decodeEnrollmentRequest(token)
    expect(decoded).toEqual(baseRequest({ name: "example-workstation" }) as EnrollmentRequest)
    expect(encodeEnrollmentRequest(decoded)).toBe(token)
  })

  it("is deterministic for the same account and arguments", () => {
    expect(encodeEnrollmentRequest(baseRequest())).toBe(encodeEnrollmentRequest(baseRequest()))
    expect(encodeEnrollmentRequest(baseRequest({ name: "a" })))
      .not.toBe(encodeEnrollmentRequest(baseRequest({ name: "b" })))
    expect(encodeEnrollmentRequest(baseRequest({ account: "org:7" })))
      .not.toBe(encodeEnrollmentRequest(baseRequest()))
  })

  it("does not depend on the caller's property order", () => {
    const reordered = {
      platform: "linux",
      public_key: device.publicKey,
      client_id: device.clientId,
      account: "user:1",
      origin: "https://vault.example",
      version: 1,
    } as EnrollmentRequest
    expect(encodeEnrollmentRequest(reordered)).toBe(encodeEnrollmentRequest(baseRequest()))
  })

  it("carries public registration material only", async () => {
    const token = encodeEnrollmentRequest(baseRequest({ name: "example-workstation" }))
    const json = decodedJson(token)
    expect(Object.keys(json)).toEqual([
      "version",
      "origin",
      "account",
      "client_id",
      "public_key",
      "platform",
      "name",
    ])
    const text = JSON.stringify(json)
    for (const secret of ["d", "p", "q", "dp", "dq", "qi"]) {
      expect(json.public_key as Record<string, unknown>).not.toHaveProperty(secret)
      expect(text).not.toContain(String((device.privateKey as Record<string, string>)[secret]))
    }
    expect(text).not.toContain("wrapped_account_key")
    expect(text).not.toContain("recovery")
    expect(text).not.toContain("token")
  })

  it("omits an absent display name instead of encoding null", () => {
    expect(decodedJson(encodeEnrollmentRequest(baseRequest()))).not.toHaveProperty("name")
    expect(canonicalEnrollmentJson(baseRequest())).not.toContain("name")
  })
})

describe("enrollment request validation", () => {
  it("rejects a malformed token", async () => {
    await expect(decodeEnrollmentRequest("not base64!!")).rejects.toThrow("malformed")
    await expect(decodeEnrollmentRequest(encodeBase64(encoder.encode("not json")))).rejects.toThrow("malformed")
    await expect(decodeEnrollmentRequest(tokenOf([1, 2, 3]))).rejects.toThrow("malformed")
    await expect(decodeEnrollmentRequest("")).rejects.toThrow("malformed")
  })

  it("rejects an unknown version", async () => {
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), version: 2 })))
      .rejects.toThrow("Unsupported enrollment request version")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), version: "1" })))
      .rejects.toThrow("Unsupported enrollment request version")
  })

  it("rejects unsupported fields", async () => {
    await expect(
      decodeEnrollmentRequest(tokenOf({ ...baseRequest(), private_key: device.privateKey }))
    ).rejects.toThrow("unsupported field: private_key")
    await expect(
      decodeEnrollmentRequest(tokenOf({ ...baseRequest(), wrapped_account_key: "x" }))
    ).rejects.toThrow("unsupported field: wrapped_account_key")
  })

  it("rejects a client ID that is not the public key's fingerprint", async () => {
    const other = await generateDeviceKey()
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), client_id: other.clientId })))
      .rejects.toThrow("client ID does not match its public key")
  })

  it("rejects a non-canonical account, origin, platform, or name", async () => {
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), account: "circlesac" })))
      .rejects.toThrow("canonical account")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), account: "org:example-org" })))
      .rejects.toThrow("canonical account")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), account: "user:1.5" })))
      .rejects.toThrow("canonical account")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), origin: "https://vault.example/circlesac" })))
      .rejects.toThrow("normalized Vault origin")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), origin: "https://vault.example/" })))
      .rejects.toThrow("normalized Vault origin")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), platform: "Darwin Kernel" })))
      .rejects.toThrow("platform is invalid")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), name: " padded " })))
      .rejects.toThrow("name is invalid")
    await expect(decodeEnrollmentRequest(tokenOf({ ...baseRequest(), name: "x".repeat(65) })))
      .rejects.toThrow("name is invalid")
  })
})

describe("public JWK contract", () => {
  it("accepts the generated public key and returns it canonically ordered", () => {
    expect(Object.keys(assertPublicJwk(device.publicKey) as object))
      .toEqual(["alg", "e", "ext", "key_ops", "kty", "n"])
  })

  it("rejects a JWK carrying private RSA parameters", () => {
    expect(() => assertPublicJwk(device.privateKey)).toThrow("must contain exactly")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), d: "private" }))
      .toThrow("must contain exactly")
  })

  it("rejects the wrong algorithm, exponent, or usage", () => {
    expect(() => assertPublicJwk({ ...(device.publicKey as object), alg: "RSA-OAEP-512" }))
      .toThrow("RSA-OAEP with SHA-256")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), e: "AQABAQ" }))
      .toThrow("exponent 65537")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), kty: "EC" }))
      .toThrow("must be an RSA key")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), key_ops: ["encrypt", "decrypt"] }))
      .toThrow("public operations only")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), key_ops: ["decrypt"] }))
      .toThrow("public operations only")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), ext: false }))
      .toThrow("must be extractable")
  })

  it("rejects a modulus that is not 3072 bits", async () => {
    const short = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"]
    )
    const jwk = await crypto.subtle.exportKey("jwk", short.publicKey)
    expect(() => assertPublicJwk(canonicalPublicJwk(jwk))).toThrow("3072-bit modulus")
    const leadingZero = encodeBase64(new Uint8Array([0, ...decodeBase64((device.publicKey as { n: string }).n).slice(1)]))
    expect(() => assertPublicJwk({ ...(device.publicKey as object), n: leadingZero })).toThrow("3072-bit modulus")
    expect(() => assertPublicJwk({ ...(device.publicKey as object), n: "not base64url!" }))
      .toThrow("must be base64url")
  })

  it("rejects non-objects", () => {
    expect(() => assertPublicJwk(null)).toThrow("must be a JWK object")
    expect(() => assertPublicJwk("key")).toThrow("must be a JWK object")
    expect(() => assertPublicJwk([device.publicKey])).toThrow("must be a JWK object")
  })
})

describe("display helpers", () => {
  it("groups the fingerprint for human comparison without changing it", () => {
    const formatted = formatFingerprint(device.clientId)
    expect(formatted.startsWith("SHA256:")).toBe(true)
    expect(formatted.replace("SHA256:", "").split(" ").join("")).toBe(device.clientId)
    expect(formatFingerprint(device.clientId)).toBe(formatted)
  })

  it("normalizes the Vault origin to scheme and host", () => {
    expect(normalizeVaultOrigin("https://vault.crcl.es/circlesac")).toBe("https://vault.crcl.es")
    expect(normalizeVaultOrigin("https://vault.circles.ac")).toBe("https://vault.circles.ac")
    expect(normalizeVaultOrigin("http://127.0.0.1:8787/org")).toBe("http://127.0.0.1:8787")
    expect(() => normalizeVaultOrigin("ftp://vault.example")).toThrow("not an HTTP origin")
  })

  it("bounds the display name", () => {
    expect(normalizeClientName(undefined)).toBeUndefined()
    expect(normalizeClientName("  ")).toBeUndefined()
    expect(normalizeClientName(" example-workstation ")).toBe("example-workstation")
    expect(() => normalizeClientName("x".repeat(65))).toThrow("at most 64")
    expect(() => normalizeClientName("bad\nname")).toThrow("printable ASCII")
  })
})
