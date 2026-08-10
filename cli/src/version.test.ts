import { describe, expect, it } from "bun:test"
import { spawnSync } from "node:child_process"
import { join } from "node:path"
import pkg from "../package.json"

describe("CLI version", () => {
  it("prints the package version without showing help", () => {
    const result = spawnSync("bun", ["run", "cli/src/index.ts", "--version"], {
      cwd: join(import.meta.dir, "../.."),
      env: { ...process.env, CI: "1" },
      encoding: "utf8",
    })

    expect(result.status).toBe(0)
    expect(result.stderr).toBe("")
    expect(result.stdout.trim()).toBe((pkg as { version?: string }).version || "dev")
  })
})
