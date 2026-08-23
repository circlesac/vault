import { describe, expect, it } from "bun:test"
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawnSync } from "node:child_process"
import { encodeBase64, type DeviceKey } from "./e2ee-crypto"
import {
  loadDeviceKey,
  readLineFromFd,
  readEncryptedKeyFile,
  saveDeviceKey,
  writeEncryptedKeyFile,
} from "./key-store"

async function storedPath(root: string, origin: string): Promise<{ account: string; path: string }> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(origin))
  const account = encodeBase64(new Uint8Array(digest)).slice(0, 32)
  return { account, path: join(root, "cvlt", "keys", `${account}.json.enc`) }
}

function deviceKey(): DeviceKey {
  return {
    clientId: "test-client-id",
    publicKey: { kty: "RSA", n: "public-marker", e: "AQAB" },
    privateKey: { kty: "RSA", n: "public-marker", e: "AQAB", d: "private-marker" },
  }
}

describe("device key store", () => {
  it("reads a confirmation line from any console-compatible file descriptor", () => {
    const root = mkdtempSync(join(tmpdir(), "cvlt-line-reader-"))
    const path = join(root, "input")
    writeFileSync(path, "  yes  \r\nignored")
    const fd = openSync(path, "r")
    try {
      expect(readLineFromFd(fd)).toBe("yes")
    } finally {
      closeSync(fd)
      rmSync(root, { recursive: true, force: true })
    }
  })

  it("round-trips through the passphrase-encrypted fallback without plaintext", async () => {
    const root = mkdtempSync(join(tmpdir(), "cvlt-key-store-fallback-"))
    const origin = `https://fallback-${Date.now()}.invalid`
    const previous = {
      config: process.env.XDG_CONFIG_HOME,
      passphrase: process.env.CVLT_KEYSTORE_PASSPHRASE,
    }
    try {
      process.env.XDG_CONFIG_HOME = root
      process.env.CVLT_KEYSTORE_PASSPHRASE = "test-only-passphrase-32-bytes"
      const stored = await storedPath(root, origin)
      await writeEncryptedKeyFile(stored.account, JSON.stringify(deviceKey()))
      const raw = readFileSync(stored.path)
      expect(raw.toString("utf8")).not.toContain("private-marker")
      expect(JSON.parse((await readEncryptedKeyFile(stored.account))!)).toEqual(deviceKey())
      if (process.platform !== "win32") expect(statSync(stored.path).mode & 0o777).toBe(0o600)

      process.env.CVLT_KEYSTORE_PASSPHRASE = "wrong-test-passphrase"
      await expect(readEncryptedKeyFile(stored.account)).rejects.toThrow()
    } finally {
      if (previous.config === undefined) delete process.env.XDG_CONFIG_HOME
      else process.env.XDG_CONFIG_HOME = previous.config
      if (previous.passphrase === undefined) delete process.env.CVLT_KEYSTORE_PASSPHRASE
      else process.env.CVLT_KEYSTORE_PASSPHRASE = previous.passphrase
      rmSync(root, { recursive: true, force: true })
    }
  })

  if (process.env.CVLT_TEST_OS_KEYSTORE === "1") {
    it(`round-trips through the ${process.platform} OS credential store`, async () => {
      const root = mkdtempSync(join(tmpdir(), "cvlt-key-store-os-"))
      const origin = process.platform === "linux"
        ? "https://linux-option-104.invalid"
        : `https://os-store-${process.platform}-${Date.now()}.invalid`
      const previous = {
        config: process.env.XDG_CONFIG_HOME,
        passphrase: process.env.CVLT_KEYSTORE_PASSPHRASE,
      }
      const stored = await storedPath(root, origin)
      try {
        process.env.XDG_CONFIG_HOME = root
        delete process.env.CVLT_KEYSTORE_PASSPHRASE
        await saveDeviceKey(origin, deviceKey())
        expect(await loadDeviceKey(origin)).toEqual(deviceKey())
        if (process.platform === "win32") {
          expect(readFileSync(stored.path).toString("utf8")).not.toContain("private-marker")
        } else {
          expect(existsSync(stored.path)).toBe(false)
        }
      } finally {
        if (process.platform === "darwin") {
          spawnSync("security", ["delete-generic-password", "-s", "circlesac.cvlt", "-a", stored.account], {
            stdio: "ignore",
          })
        } else if (process.platform === "linux") {
          spawnSync("secret-tool", ["clear", "--", "service", "circlesac.cvlt", "account", stored.account], {
            stdio: "ignore",
          })
        }
        if (previous.config === undefined) delete process.env.XDG_CONFIG_HOME
        else process.env.XDG_CONFIG_HOME = previous.config
        if (previous.passphrase === undefined) delete process.env.CVLT_KEYSTORE_PASSPHRASE
        else process.env.CVLT_KEYSTORE_PASSPHRASE = previous.passphrase
        rmSync(root, { recursive: true, force: true })
      }
    }, 15_000)
  } else {
    it.skip("round-trips through the host OS credential store", () => {})
  }
})
