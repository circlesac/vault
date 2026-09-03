import { describe, it, expect } from "bun:test"
import { parseRef, isSecretRef, parseVaultCoordinate, injectTemplate, parseEnvFile, buildRunEnv } from "./refs"

// ── op:// — guards the historical parseSecretRef behavior exactly ────────────

describe("parseRef: op://", () => {
  it("parses vault/item/field", () => {
    const r = parseRef("op://my-vault/db-credentials/password")
    expect(r).toEqual({
      ok: true,
      ref: { scheme: "op", vault: "my-vault", item: "db-credentials", field: "password" },
    })
  })

  it("preserves case and spaces (free-form 1Password names)", () => {
    const r = parseRef("op://Compat Vault/Compat Login/username")
    expect(r.ok && r.ref.scheme === "op" && r.ref.vault).toBe("Compat Vault")
  })

  it("ignores a ?query suffix (op ssh-format idiom)", () => {
    const r = parseRef("op://Personal/Test SSH/private key?ssh-format=openssh")
    expect(r.ok && r.ref.scheme === "op" && r.ref.field).toBe("private key")
  })

  it("takes the third segment as field when extra segments exist (historical)", () => {
    const r = parseRef("op://vault/item/section/field")
    expect(r.ok && r.ref.scheme === "op" && r.ref.field).toBe("section")
  })

  it("rejects refs with fewer than three segments", () => {
    expect(parseRef("op://vault/item").ok).toBe(false)
    expect(parseRef("op://vault").ok).toBe(false)
  })
})

// ── vlt:// — uppercase secret names with optional stage suffix ───────────────

describe("parseRef: vlt://", () => {
  it("parses owner-global refs", () => {
    expect(parseRef("vlt://github.com/circlesac/OPENAI_KEY")).toEqual({
      ok: true,
      ref: { scheme: "cvlt", provider: "github.com", owner: "circlesac", repo: null, name: "OPENAI_KEY" },
    })
  })

  it("parses project refs and lowercases owner/repo", () => {
    expect(parseRef("vlt://github.com/CirclesAc/Vault/DB_PASSWORD")).toEqual({
      ok: true,
      ref: { scheme: "cvlt", provider: "github.com", owner: "circlesac", repo: "vault", name: "DB_PASSWORD" },
    })
  })

  it("parses GitHub-prefixed names with hyphenated stage suffixes", () => {
    expect(parseRef("vlt://github.com/circlesac/padawan-v2/GITHUB_APP_ID-DEV")).toEqual({
      ok: true,
      ref: { scheme: "cvlt", provider: "github.com", owner: "circlesac", repo: "padawan-v2", name: "GITHUB_APP_ID-DEV" },
    })
  })

  const bad = [
    ["CJK owner", "vlt://github.com/한글/NAME"],
    ["percent-encoded slash", "vlt://github.com/owner%2Frepo/NAME"],
    ["digit-start NAME", "vlt://github.com/o/1NAME"],
    ["lowercase NAME", "vlt://github.com/o/name"],
    ["lowercase after prefix", "vlt://github.com/o/GITHUB_token"],
    ["invalid punctuation", "vlt://github.com/o/GITHUB_TOKEN!"],
    ["unknown provider", "vlt://gitlab.com/o/NAME"],
    ["no NAME (2 segments)", "vlt://github.com/owner"],
    ["too many segments", "vlt://github.com/o/r/x/NAME"],
    ["uses # instead of /", "vlt://github.com/owner/repo#NAME"],
    ["unknown scheme", "secret://github.com/o/NAME"],
  ] as const
  for (const [label, ref] of bad) {
    it(`rejects ${label}`, () => {
      expect(parseRef(ref).ok).toBe(false)
    })
  }
})

// ── Substitution ──────────────────────────────────────────────────────────────

const FAKE: Record<string, string> = {
  "op://v/i/f": "op-value",
  "vlt://github.com/circlesac/API_KEY": "cvlt-value",
  "vlt://github.com/circlesac/app/DB_PASSWORD": "project-value",
}
const resolver = async (ref: string) => {
  if (!(ref in FAKE)) throw new Error(`unknown ref ${ref}`)
  return FAKE[ref]!
}

describe("injectTemplate", () => {
  it("replaces both op:// and vlt:// references", async () => {
    const out = await injectTemplate(
      "A={{op://v/i/f}}\nB={{vlt://github.com/circlesac/API_KEY}}\nC=plain",
      resolver
    )
    expect(out).toBe("A=op-value\nB=cvlt-value\nC=plain")
  })

  it("leaves non-reference braces alone", async () => {
    expect(await injectTemplate("X={{not-a-ref}}", resolver)).toBe("X={{not-a-ref}}")
  })

  it("resolves unique references concurrently", async () => {
    const calls: string[] = []
    const out = await injectTemplate(
      "A={{op://v/i/f}} B={{op://v/i/f}} C={{vlt://github.com/circlesac/API_KEY}}",
      async (ref) => {
        calls.push(ref)
        await Bun.sleep(10)
        return FAKE[ref]!
      }
    )
    expect(out).toBe("A=op-value B=op-value C=cvlt-value")
    expect(calls.sort()).toEqual([
      "op://v/i/f",
      "vlt://github.com/circlesac/API_KEY",
    ])
  })
})

describe("parseEnvFile", () => {
  it("parses KEY=value lines, skipping comments and blanks", () => {
    expect(parseEnvFile("# c\n\nA=1\nB=vlt://github.com/o/N\n =bad\nC=x=y")).toEqual({
      A: "1",
      B: "vlt://github.com/o/N",
      C: "x=y",
    })
  })
})

describe("buildRunEnv", () => {
  it("resolves refs from env-file and parent env, passes plain values through", async () => {
    const env = await buildRunEnv(
      { HOME: "/home/x", TOKEN: "op://v/i/f" },
      "DB_PASSWORD=vlt://github.com/circlesac/app/DB_PASSWORD\nPLAIN=hello",
      resolver
    )
    expect(env.HOME).toBe("/home/x")
    expect(env.TOKEN).toBe("op-value")
    expect(env.DB_PASSWORD).toBe("project-value")
    expect(env.PLAIN).toBe("hello")
  })

  it("env-file entries override parent env", async () => {
    const env = await buildRunEnv(
      { DB_PASSWORD: "stale" },
      "DB_PASSWORD=vlt://github.com/circlesac/app/DB_PASSWORD",
      resolver
    )
    expect(env.DB_PASSWORD).toBe("project-value")
  })

  it("resolves each unique merged reference once", async () => {
    const calls: string[] = []
    const env = await buildRunEnv(
      {
        TOKEN: "op://v/i/f",
        TOKEN_COPY: "op://v/i/f",
        DB_PASSWORD: "stale",
      },
      "DB_PASSWORD=vlt://github.com/circlesac/app/DB_PASSWORD",
      async (ref) => {
        calls.push(ref)
        await Bun.sleep(10)
        return FAKE[ref]!
      }
    )
    expect(env.TOKEN).toBe("op-value")
    expect(env.TOKEN_COPY).toBe("op-value")
    expect(env.DB_PASSWORD).toBe("project-value")
    expect(calls.sort()).toEqual([
      "op://v/i/f",
      "vlt://github.com/circlesac/app/DB_PASSWORD",
    ])
  })
})

describe("isSecretRef", () => {
  it("detects both schemes", () => {
    expect(isSecretRef("op://a/b/c")).toBe(true)
    expect(isSecretRef("vlt://github.com/o/N")).toBe(true)
    expect(isSecretRef("plain")).toBe(false)
  })
})

describe("parseVaultCoordinate", () => {
  it("parses project and owner-global coordinates, lowercasing", () => {
    expect(parseVaultCoordinate("github.com/CirclesAc/My-App")).toEqual({
      provider: "github.com",
      owner: "circlesac",
      repo: "my-app",
    })
    expect(parseVaultCoordinate("github.com/circlesac")).toEqual({
      provider: "github.com",
      owner: "circlesac",
      repo: null,
    })
  })

  it("returns null for free-form op:// vault names", () => {
    expect(parseVaultCoordinate("My Passwords")).toBeNull()
    expect(parseVaultCoordinate("circlesac/my-app")).toBeNull() // no provider → free-form
    expect(parseVaultCoordinate("gitlab.com/owner/repo")).toBeNull() // unknown provider
    expect(parseVaultCoordinate("github.com/한글")).toBeNull()
    expect(parseVaultCoordinate("github.com/o/r/extra")).toBeNull()
  })
})
