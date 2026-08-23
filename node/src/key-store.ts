import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, readSync, writeFileSync, closeSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { spawnSync } from "node:child_process"
import type { DeviceKey } from "./e2ee-crypto"
import { decodeBase64, encodeBase64 } from "./e2ee-crypto"

const encoder = new TextEncoder()
const decoder = new TextDecoder()

async function accountName(origin: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(origin))
  return encodeBase64(new Uint8Array(digest)).slice(0, 32)
}

function configPath(account: string): string {
  const root = process.env.XDG_CONFIG_HOME || join(homedir(), ".config")
  return join(root, "cvlt", "keys", `${account}.json.enc`)
}

function macRead(account: string): string | null {
  const result = spawnSync(
    "security",
    ["find-generic-password", "-s", "circlesac.cvlt", "-a", account, "-w"],
    { encoding: "utf8" }
  )
  return result.status === 0 ? result.stdout.trim() : null
}

function macWrite(account: string, value: string): boolean {
  const result = spawnSync(
    "security",
    ["add-generic-password", "-U", "-s", "circlesac.cvlt", "-a", account, "-w", value],
    { encoding: "utf8" }
  )
  return result.status === 0
}

function linuxRead(account: string): string | null {
  const result = spawnSync("secret-tool", ["lookup", "--", "service", "circlesac.cvlt", "account", account], {
    encoding: "utf8",
  })
  return result.status === 0 && result.stdout.trim() ? result.stdout.trim() : null
}

function linuxWrite(account: string, value: string): boolean {
  const result = spawnSync(
    "secret-tool",
    ["store", "--label", "Circles Vault client key", "--", "service", "circlesac.cvlt", "account", account],
    { input: value, encoding: "utf8" }
  )
  if (process.env.CVLT_TEST_OS_KEYSTORE === "1" && result.status !== 0) {
    throw new Error(`Linux Secret Service failed: ${result.error?.message || result.stderr.trim() || `exit ${result.status}`}`)
  }
  return result.status === 0
}

function windowsScript(path: string, operation: "read" | "write"): string {
  const escaped = path.replace(/'/g, "''")
  const prefix = "$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Security;"
  if (operation === "write") {
    return `${prefix}$value=[Console]::In.ReadToEnd();$bytes=[Text.Encoding]::UTF8.GetBytes($value);$enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName('${escaped}'))|Out-Null;[IO.File]::WriteAllBytes('${escaped}',$enc)`
  }
  return `${prefix}if(Test-Path '${escaped}'){$enc=[IO.File]::ReadAllBytes('${escaped}');$bytes=[System.Security.Cryptography.ProtectedData]::Unprotect($enc,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);[Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))}`
}

function windowsRead(account: string): string | null {
  const path = configPath(account)
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", windowsScript(path, "read")], {
    encoding: "utf8",
  })
  return result.status === 0 && result.stdout ? result.stdout : null
}

function windowsWrite(account: string, value: string): boolean {
  const path = configPath(account)
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", windowsScript(path, "write")], {
    input: value,
    encoding: "utf8",
  })
  if (process.env.CVLT_TEST_OS_KEYSTORE === "1" && result.status !== 0) {
    throw new Error(`Windows DPAPI failed: ${result.error?.message || result.stderr.trim() || `exit ${result.status}`}`)
  }
  return result.status === 0
}

export function promptSecret(prompt: string): string {
  const supplied = process.env.CVLT_KEYSTORE_PASSPHRASE
  if (supplied) {
    if (supplied.length < 12) throw new Error("Key-store passphrase must be at least 12 characters")
    return supplied
  }
  if (!process.stdin.isTTY) {
    throw new Error("No OS credential store is available; run cvlt in a terminal to unlock the encrypted key file")
  }
  process.stderr.write(prompt)
  const tty = openSync("/dev/tty", "r+")
  spawnSync("stty", ["-echo"], { stdio: [tty, tty, tty] })
  const bytes: number[] = []
  const buffer = Buffer.alloc(1)
  try {
    while (readSync(tty, buffer, 0, 1, null) === 1) {
      if (buffer[0] === 10 || buffer[0] === 13) break
      bytes.push(buffer[0]!)
    }
  } finally {
    spawnSync("stty", ["echo"], { stdio: [tty, tty, tty] })
    closeSync(tty)
    process.stderr.write("\n")
  }
  const value = Buffer.from(bytes).toString("utf8")
  if (value.length < 12) throw new Error("Key-store passphrase must be at least 12 characters")
  return value
}

/**
 * Read one visible line from the controlling terminal. Used for confirmations
 * that must not be satisfiable by piped stdin, and never for secrets — the
 * prompt and the echoed answer both stay on the terminal, not on stdout.
 */
export function readLineFromFd(fd: number): string {
  const bytes: number[] = []
  const buffer = Buffer.alloc(1)
  while (readSync(fd, buffer, 0, 1, null) === 1) {
    if (buffer[0] === 10 || buffer[0] === 13) break
    bytes.push(buffer[0]!)
  }
  return Buffer.from(bytes).toString("utf8").trim()
}

export function promptLine(prompt: string): string {
  if (!process.stdin.isTTY) {
    throw new Error("This action needs an explicit confirmation; run it in a terminal")
  }
  process.stderr.write(prompt)
  return readLineFromFd(process.stdin.fd)
}

async function fallbackKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"])
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  )
}

export async function readEncryptedKeyFile(account: string): Promise<string | null> {
  const path = configPath(account)
  if (!existsSync(path)) return null
  const stored = JSON.parse(readFileSync(path, "utf8")) as { salt: string; nonce: string; ciphertext: string }
  const passphrase = promptSecret("Vault key-store passphrase: ")
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64(stored.nonce), additionalData: encoder.encode(`cvlt:${account}`) },
    await fallbackKey(passphrase, decodeBase64(stored.salt)),
    decodeBase64(stored.ciphertext)
  )
  return decoder.decode(plaintext)
}

export async function writeEncryptedKeyFile(account: string, value: string): Promise<boolean> {
  const path = configPath(account)
  const passphrase = promptSecret("Create vault key-store passphrase: ")
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(`cvlt:${account}`) },
    await fallbackKey(passphrase, salt),
    encoder.encode(value)
  )
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, JSON.stringify({ salt: encodeBase64(salt), nonce: encodeBase64(nonce), ciphertext: encodeBase64(new Uint8Array(ciphertext)) }), { mode: 0o600 })
  chmodSync(path, 0o600)
  return true
}

export async function loadDeviceKey(origin: string): Promise<DeviceKey | null> {
  const account = await accountName(origin)
  let value: string | null = null
  if (process.platform === "darwin") value = macRead(account)
  else if (process.platform === "win32") value = windowsRead(account)
  else value = linuxRead(account)
  if (value === null) value = await readEncryptedKeyFile(account)
  return value ? JSON.parse(value) as DeviceKey : null
}

export async function saveDeviceKey(origin: string, key: DeviceKey): Promise<void> {
  const account = await accountName(origin)
  const value = JSON.stringify(key)
  let stored = false
  if (process.platform === "darwin") stored = macWrite(account, value)
  else if (process.platform === "win32") stored = windowsWrite(account, value)
  else stored = linuxWrite(account, value)
  if (!stored) stored = await writeEncryptedKeyFile(account, value)
  if (!stored) throw new Error("Unable to store the vault client key securely")
}
