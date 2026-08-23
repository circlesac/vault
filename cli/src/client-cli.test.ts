import { afterAll, beforeAll, describe, expect, it } from "bun:test"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createFakeVault, type FakeVault } from "../../node/src/fake-vault"
import {
  decodeBase64,
  encodeBase64,
  generateDeviceKey,
  type DeviceKey,
} from "../../node/src/e2ee-crypto"
import { writeEncryptedKeyFile } from "../../node/src/key-store"

/**
 * Drives the compiled command surface against a live local Vault stand-in and
 * two genuinely separate key stores. This is the in-repo counterpart of the
 * development two-client harness: it proves the wire protocol, the enrollment
 * round trip, and the stdout/stderr split without needing a deployment.
 */

const repoRoot = join(import.meta.dir, "../..")
const PASSPHRASE = "cvlt-client-cli-test-passphrase"
const decoder = new TextDecoder()
const describeWithPty = process.platform === "win32" ? describe.skip : describe

let sandbox = ""
let shims = ""
let storeA = ""
let storeB = ""
let origin = ""
let server: ReturnType<typeof Bun.serve> | null = null
let vault: FakeVault
let deviceA: DeviceKey
let deviceB: DeviceKey
const previousPassphrase = process.env.CVLT_KEYSTORE_PASSPHRASE
const previousPath = process.env.PATH
const previousConfigHome = process.env.XDG_CONFIG_HOME

async function keyStoreAccount(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
  return encodeBase64(new Uint8Array(digest)).slice(0, 32)
}

async function seed(store: string, device: DeviceKey) {
  process.env.XDG_CONFIG_HOME = store
  process.env.CVLT_KEYSTORE_PASSPHRASE = PASSPHRASE
  await writeEncryptedKeyFile(await keyStoreAccount(origin), JSON.stringify(device))
}

/**
 * Spawns asynchronously on purpose: the fake Vault runs on this process's
 * event loop, so a synchronous child would deadlock waiting for a reply that
 * this process cannot send.
 */
async function runCli(
  store: string,
  args: string[]
): Promise<{ status: number; stdout: string; stderr: string }> {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    CI: "1",
    CVLT_NO_UPDATE_CHECK: "1",
    PATH: `${shims}:${process.env.PATH ?? ""}`,
    XDG_CONFIG_HOME: store,
    CVLT_KEYSTORE_PASSPHRASE: PASSPHRASE,
    OP_CONNECT_HOST: origin,
    OP_CONNECT_TOKEN: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyOjEifQ.signature",
  }
  delete env.ACTIONS_ID_TOKEN_REQUEST_URL
  delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  const child = Bun.spawn(["bun", "run", "cli/src/index.ts", ...args], {
    cwd: repoRoot,
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { status, stdout, stderr }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

async function runCliInPty(
  store: string,
  args: string[],
  input: string
): Promise<{ status: number; output: string }> {
  const command = ["bun", "run", "cli/src/index.ts", ...args]
  const argv = process.platform === "darwin"
    ? [
        "expect",
        "-c",
        [
          "set timeout 30",
          "log_user 1",
          "spawn -noecho sh -c $env(CVLT_TEST_PTY_COMMAND)",
          "after 200",
          "send -- $env(CVLT_TEST_PTY_INPUT)",
          "expect eof",
          "set result [wait]",
          "exit [lindex $result 3]",
        ].join("; "),
      ]
    : ["script", "-qec", command.map(shellQuote).join(" "), "/dev/null"]
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    CI: "1",
    CVLT_NO_UPDATE_CHECK: "1",
    PATH: `${shims}:${process.env.PATH ?? ""}`,
    XDG_CONFIG_HOME: store,
    CVLT_KEYSTORE_PASSPHRASE: PASSPHRASE,
    OP_CONNECT_HOST: origin,
    OP_CONNECT_TOKEN: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyOjEifQ.signature",
    CVLT_TEST_PTY_INPUT: input.replace(/\n/g, "\r"),
    // BSD script cannot take commands from a socket-backed stdin. Expect is
    // the macOS PTY driver; Linux uses GNU script above.
    CVLT_TEST_PTY_COMMAND: command.map(shellQuote).join(" "),
  }
  delete env.ACTIONS_ID_TOKEN_REQUEST_URL
  delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  const child = Bun.spawn(argv, {
    cwd: repoRoot,
    env,
    stdin: process.platform === "darwin" ? "ignore" : "pipe",
    stdout: "pipe",
    stderr: "pipe",
  })
  if (process.platform !== "darwin") {
    child.stdin.write(input)
    child.stdin.end()
  }
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { status, output: `${stdout}${stderr}` }
}

beforeAll(async () => {
  sandbox = mkdtempSync(join(tmpdir(), "cvlt-client-cli-"))
  shims = join(sandbox, "bin")
  storeA = join(sandbox, "store-a")
  storeB = join(sandbox, "store-b")
  mkdirSync(shims, { recursive: true })
  mkdirSync(storeA, { recursive: true })
  mkdirSync(storeB, { recursive: true })
  // Force both installations onto the passphrase-encrypted fallback so the two
  // stores are independent, the way two machines or two OS users would be.
  for (const name of ["security", "secret-tool", "powershell.exe"]) {
    writeFileSync(join(shims, name), "#!/bin/sh\nexit 1\n", { mode: 0o755 })
  }
  process.env.PATH = `${shims}:${process.env.PATH ?? ""}`

  deviceA = await generateDeviceKey()
  deviceB = await generateDeviceKey()
  vault = createFakeVault({ account: "user:1" })
  server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: vault.handle })
  origin = `http://127.0.0.1:${server.port}`

  await vault.register(deviceA, { name: "approver", platform: "darwin" })
  await seed(storeA, deviceA)
  await seed(storeB, deviceB)
}, 60_000)

afterAll(() => {
  server?.stop(true)
  if (previousPassphrase === undefined) delete process.env.CVLT_KEYSTORE_PASSPHRASE
  else process.env.CVLT_KEYSTORE_PASSPHRASE = previousPassphrase
  if (previousPath === undefined) delete process.env.PATH
  else process.env.PATH = previousPath
  if (previousConfigHome === undefined) delete process.env.XDG_CONFIG_HOME
  else process.env.XDG_CONFIG_HOME = previousConfigHome
  rmSync(sandbox, { recursive: true, force: true })
})

describeWithPty("cvlt client PTY integration", () => {
  it("enrolls a second installation and keeps stdout a stable data surface", async () => {
    const request = await runCli(storeB, ["client", "request", "--name", "example-workstation"])
    expect(request.status).toBe(0)

    // stdout is the enrollment token and nothing else.
    const token = request.stdout.trim()
    expect(request.stdout).toBe(`${token}\n`)
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
    const decoded = JSON.parse(decoder.decode(decodeBase64(token))) as Record<string, unknown>
    expect(decoded).toEqual({
      version: 1,
      origin,
      account: "user:1",
      client_id: deviceB.clientId,
      public_key: deviceB.publicKey,
      platform: process.platform,
      name: "example-workstation",
    })

    // Diagnostics and the fingerprint go to stderr.
    expect(request.stderr).toContain("Fingerprint:")
    expect(request.stderr).toContain(deviceB.clientId.slice(0, 8))
    expect(request.stderr).toContain(origin)
    expect(request.stderr).toContain("Reused this Vault origin's existing installation key.")
    expect(request.stdout).not.toContain("Fingerprint")
    expect(request.stdout).not.toContain(String((deviceB.privateKey as Record<string, string>).d))

    // Repeating the request is deterministic.
    expect((await runCli(storeB, ["client", "request", "--name", "example-workstation"])).stdout).toBe(request.stdout)

    // Before approval B cannot manage anything.
    const beforeApproval = await runCli(storeB, ["client", "list"])
    expect(beforeApproval.status).toBe(1)
    expect(beforeApproval.stderr).toContain("This installation is not registered")

    const approve = await runCliInPty(storeA, ["client", "approve", token], "yes\n")
    expect(approve.status, approve.output).toBe(0)
    expect(approve.output).toContain("Approve this installation?")
    expect(approve.output).toContain("The fingerprint must match the one shown on the requesting machine.")
    expect(approve.output).toContain(`Approved installation ${deviceB.clientId}`)
    expect(vault.clients.get(deviceB.clientId)?.revoked).toBe(false)

    const listed = await runCli(storeA, ["client", "list", "--format", "json"])
    expect(listed.status).toBe(0)
    expect(listed.stderr).toBe("")
    const clients = JSON.parse(listed.stdout) as { id: string; is_current: boolean; name: string | null }[]
    expect(clients).toEqual([
      expect.objectContaining({ id: deviceA.clientId, is_current: true }),
      expect.objectContaining({ id: deviceB.clientId, is_current: false, name: "example-workstation" }),
    ])
    expect(listed.stdout).not.toContain("public_key")
    expect(listed.stdout).not.toContain("wrapped")

    // B is registered now, so its own request reports that instead of a token.
    const settled = await runCli(storeB, ["client", "request"])
    expect(settled.status).toBe(0)
    expect(settled.stdout).toBe("")
    expect(settled.stderr).toContain("already registered")
  }, 120_000)

  it("will not approve without an explicit confirmation", async () => {
    await vault.register(deviceB, { revoked: true })
    const request = await runCli(storeB, ["client", "request"])
    expect(request.status).toBe(0)
    const approve = await runCli(storeA, ["client", "approve", request.stdout.trim()])
    expect(approve.status).toBe(1)
    expect(approve.stderr).toContain("Approve this installation?")
    expect(approve.stderr).toContain("explicit confirmation")
    expect(approve.stdout).toBe("")
    expect(vault.clients.get(deviceB.clientId)?.revoked).toBe(true)
    // Restore the enrolled state the following cases start from.
    await vault.register(deviceB, { name: "example-workstation", platform: process.platform })
  }, 60_000)

  it("refuses to approve a request from another deployment", async () => {
    const foreign = encodeBase64(new TextEncoder().encode(JSON.stringify({
      version: 1,
      origin: "https://vault.crcl.es",
      account: "user:1",
      client_id: deviceB.clientId,
      public_key: deviceB.publicKey,
      platform: "linux",
    })))
    const result = await runCli(storeA, ["client", "approve", foreign])
    expect(result.status).toBe(1)
    expect(result.stderr).toContain("Enrollment request targets https://vault.crcl.es")
    expect(result.stdout).toBe("")
  }, 60_000)

  it("revokes the second installation and keeps the first readable", async () => {
    const revoke = await runCli(storeA, ["client", "revoke", deviceB.clientId])
    expect(revoke.status).toBe(0)
    expect(revoke.stdout).toContain(`Revoked installation ${deviceB.clientId}`)
    expect(vault.clients.get(deviceB.clientId)?.revoked).toBe(true)

    const denied = await runCli(storeB, ["client", "list"])
    expect(denied.status).toBe(1)
    expect(denied.stderr).toContain("This installation is not registered")

    const stillWorks = await runCli(storeA, ["client", "list", "--format", "json"])
    expect(stillWorks.status).toBe(0)
    expect(JSON.parse(stillWorks.stdout)).toEqual([
      expect.objectContaining({ id: deviceA.clientId, is_current: true }),
    ])

    const self = await runCli(storeA, ["client", "revoke", deviceA.clientId])
    expect(self.status).toBe(1)
    expect(self.stderr).toContain("from itself is not allowed")
    expect(vault.clients.get(deviceA.clientId)?.revoked).toBe(false)
  }, 60_000)

  it("re-enrolls the revoked installation without destructive recovery", async () => {
    const request = await runCli(storeB, ["client", "request", "--name", "example-workstation"])
    expect(request.status).toBe(0)
    const approve = await runCliInPty(storeA, ["client", "approve", request.stdout.trim()], "yes\n")
    expect(approve.status, approve.output).toBe(0)
    expect(vault.clients.get(deviceB.clientId)?.revoked).toBe(false)

    const listed = await runCli(storeB, ["client", "list", "--format", "json"])
    expect(listed.status).toBe(0)
    expect(JSON.parse(listed.stdout)).toEqual([
      expect.objectContaining({ id: deviceA.clientId, is_current: false }),
      expect.objectContaining({ id: deviceB.clientId, is_current: true }),
    ])
  }, 120_000)
})
