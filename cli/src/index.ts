#!/usr/bin/env bun

import { defineCommand, runMain } from "citty"
import pkg from "../package.json"
import {
  api,
  apiOptional,
  approveClientEnrollment,
  completeRecovery,
  doctorE2ee,
  downloadFile,
  getCirclesToken,
  getConfig,
  listClients,
  requestClientEnrollment,
  resolveItem,
  resolveVault,
  revokeClient,
  secretsApiForOwner,
  setOverrides,
  startRecovery,
  uploadFile,
} from "@circlesac/vault/cli"
import { parseRef, parseVaultCoordinate, injectTemplate, buildRunEnv } from "@circlesac/vault/cli"
import {
  applyFieldAssignments,
  isFieldAssignment,
  parseFieldAssignment,
} from "./item-fields"
import { checkForUpdate } from "./lib/update-check.ts"
import { createReadStream, readFileSync } from "node:fs"
import { writeFileSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { promptLine, promptSecret } from "@circlesac/vault/cli"
import { startConnectServer } from "./connect-server"
import { approvalPreview, clientTable, isAffirmative } from "./client-output"
import {
  mutationResult,
  mutationTarget,
  mutationTargetLine,
  type MutationTarget,
} from "./mutation-output"

type Item = {
  id: string
  title: string
  version: number
  vault: { id: string }
  category: string
  tags: string[]
  favorite: boolean
  fields?: { id: string; label: string; value: string; type: string; purpose?: string }[]
  sections?: object[]
  urls?: { href: string; primary?: boolean }[]
  created_at: string
  updated_at: string
}

type Vault = {
  id: string
  name: string
  description: string
  type: string
  items: number
  created_at: string
  updated_at: string
}

// ── Secret reading — two address surfaces (op:// + vlt://) ──────────────────

async function readSecret(ref: string): Promise<string> {
  const parsed = parseRef(ref)
  if (!parsed.ok) {
    console.error(`[ERROR] Invalid secret reference: ${ref}`)
    console.error(parsed.message)
    process.exit(1)
  }

  if (parsed.ref.scheme === "cvlt") {
    const res = await secretsApiForOwner<{ value: string }>(
      parsed.ref.owner,
      `/v1/read?ref=${encodeURIComponent(ref)}`
    )
    return res.value
  }

  const { vault, item, field } = parsed.ref
  const vaultId = await resolveVault(vault)
  const itemId = await resolveItem(vaultId, item)
  const fullItem = await api<Item>(`/v1/vaults/${vaultId}/items/${itemId}`)

  const f = fullItem.fields?.find(
    (f) => f.label === field || f.id === field || f.purpose?.toLowerCase() === field.toLowerCase()
  )
  if (!f) {
    console.error(`[ERROR] Field "${field}" not found on item "${item}"`)
    process.exit(1)
  }
  return f.value
}

// ── Commands ────────────────────────────────────────────────────────────────

const formatFlag = {
  format: { type: "string" as const, description: "Output format: json or human-readable" },
}

const vaultFlag = {
  vault: { type: "string" as const, description: "Vault name or ID" },
}

async function currentMutationTarget(): Promise<MutationTarget> {
  return mutationTarget(await getConfig())
}

async function printMutation<T extends object>(
  value: T,
  format: string | undefined,
  lines: string[]
) {
  const target = await currentMutationTarget()
  if (format === "json") {
    console.log(JSON.stringify(mutationResult(value, target), null, 2))
    return
  }
  for (const line of lines) console.log(line)
  console.log(mutationTargetLine(target))
}

// read
const readCommand = defineCommand({
  meta: { name: "read", description: "Read a secret reference" },
  args: {
    reference: { type: "positional" as const, description: "Secret reference (op://vault/item/field)", required: true },
    "no-newline": { type: "boolean" as const, alias: "n", description: "No trailing newline" },
    "out-file": { type: "string" as const, alias: "o", description: "Write to file instead of stdout" },
  },
  async run({ args }) {
    const value = await readSecret(args.reference)
    if (args["out-file"]) {
      writeFileSync(args["out-file"], value, { mode: 0o600 })
    } else if (args["no-newline"]) {
      process.stdout.write(value)
    } else {
      console.log(value)
    }
  },
})

// inject
const injectCommand = defineCommand({
  meta: { name: "inject", description: "Inject secrets into a template" },
  args: {
    "in-file": { type: "string" as const, alias: "i", description: "Input template file (default: stdin)" },
    "out-file": { type: "string" as const, alias: "o", description: "Output file (default: stdout)" },
  },
  async run({ args }) {
    let template: string
    if (args["in-file"]) {
      template = readFileSync(args["in-file"], "utf-8")
    } else {
      // Read from stdin
      const chunks: Buffer[] = []
      for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
      template = Buffer.concat(chunks).toString("utf-8")
    }

    // Replace all {{op://...}} / {{vlt://...}} references
    const result = await injectTemplate(template, (ref) => readSecret(ref))

    if (args["out-file"]) {
      writeFileSync(args["out-file"], result, { mode: 0o600 })
    } else {
      process.stdout.write(result)
    }
  },
})

// run
const runCommand = defineCommand({
  meta: { name: "run", description: "Run a command with secrets injected as env vars" },
  args: {
    "env-file": { type: "string" as const, description: "Env file with KEY=<secret reference> lines (op run idiom)" },
    "no-masking": { type: "boolean" as const, description: "Don't mask secrets in output" },
  },
  async run({ args, rawArgs }) {
    // Find -- separator
    const dashIdx = rawArgs.indexOf("--")
    if (dashIdx < 0 || dashIdx === rawArgs.length - 1) {
      console.error("Usage: vault run [flags] -- <command> [args...]")
      process.exit(1)
    }
    const cmd = rawArgs.slice(dashIdx + 1)

    // Resolve op:// and vlt:// references from --env-file entries and env vars
    const envFileContent = args["env-file"] ? readFileSync(args["env-file"], "utf-8") : null
    const env = await buildRunEnv(process.env, envFileContent, (ref) => readSecret(ref))

    const result = spawnSync(cmd[0]!, cmd.slice(1), { stdio: "inherit", env })
    process.exit(result.status ?? 1)
  },
})

// vault list
const vaultListCommand = defineCommand({
  meta: { name: "list", description: "List all vaults (op:// containers + registered repos)" },
  args: { ...formatFlag },
  async run({ args }) {
    const vaults = await api<Vault[]>("/v1/vaults")
    type Grant = { id: string; repository: string; role: string; environment?: string; ref?: string }
    // Registered coordinate vaults come from grants; OIDC callers can't list
    // grants, so this part is best-effort.
    const grants = await apiOptional<Grant[]>("/v1/oidc/grants")
    if (args.format === "json") {
      const coords = (grants ?? []).map((g) => ({
        name: `github.com/${g.repository}`,
        role: g.role,
        environment: g.environment,
        ref: g.ref,
      }))
      console.log(JSON.stringify({ vaults, registered: coords }, null, 2))
    } else {
      console.log(`${"ID".padEnd(28)} ${"NAME".padEnd(24)} ITEMS`)
      console.log("─".repeat(60))
      for (const v of vaults) {
        console.log(`${v.id.padEnd(28)} ${v.name.padEnd(24)} ${v.items}`)
      }
      if (grants && grants.length > 0) {
        console.log()
        console.log(`${"REGISTERED REPO".padEnd(44)} ${"ROLE".padEnd(6)} NARROWING`)
        console.log("─".repeat(70))
        for (const g of grants) {
          const narrowing = [g.environment && `env=${g.environment}`, g.ref && `ref=${g.ref}`]
            .filter(Boolean)
            .join(" ") || "—"
          console.log(`${`github.com/${g.repository}`.padEnd(44)} ${g.role.padEnd(6)} ${narrowing}`)
        }
      }
    }
  },
})

// vault get
const vaultGetCommand = defineCommand({
  meta: { name: "get", description: "Get vault details" },
  args: {
    vault: { type: "positional" as const, description: "Vault name or ID", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const coord = parseVaultCoordinate(args.vault)
    if (coord) {
      type Grant = { id: string; repository: string; role: string; environment?: string; ref?: string; created_at: string }
      const coordName = `${coord.provider}/${coord.owner}${coord.repo ? `/${coord.repo}` : ""}`
      const grants = coord.repo ? await api<Grant[]>("/v1/oidc/grants") : []
      const matching = grants.filter((g) => g.repository.toLowerCase() === `${coord.owner}/${coord.repo}`)
      // Secrets live as op:// items in the coordinate-named vault.
      const vault = (await api<Vault[]>("/v1/vaults")).find((v) => v.name.toLowerCase() === coordName)
      const secretCount = vault?.items ?? 0
      if (args.format === "json") {
        console.log(JSON.stringify({ name: args.vault, registrations: matching, secrets: secretCount }, null, 2))
        return
      }
      console.log(`Name:        ${args.vault}`)
      console.log(`Scope:       ${coord.repo ? "project" : "owner-global"}`)
      console.log(`Secrets:     ${secretCount}`)
      if (coord.repo) {
        if (matching.length === 0) {
          console.log("CI access:   not registered (run 'cvlt vault create' to allow this repo's CI)")
        } else {
          for (const g of matching) {
            const narrowing = [g.environment && `env=${g.environment}`, g.ref && `ref=${g.ref}`]
              .filter(Boolean)
              .join(" ")
            console.log(`CI access:   ${g.role}${narrowing ? ` (${narrowing})` : ""} since ${g.created_at}`)
          }
        }
      } else {
        console.log("CI access:   readable by every registered repo of this owner")
      }
      return
    }
    const vaultId = await resolveVault(args.vault)
    const vault = await api<Vault>(`/v1/vaults/${vaultId}`)
    if (args.format === "json") {
      console.log(JSON.stringify(vault, null, 2))
    } else {
      console.log(`ID:          ${vault.id}`)
      console.log(`Name:        ${vault.name}`)
      console.log(`Description: ${vault.description}`)
      console.log(`Items:       ${vault.items}`)
      console.log(`Created:     ${vault.created_at}`)
      console.log(`Updated:     ${vault.updated_at}`)
    }
  },
})

// vault create — two surfaces by name shape (RFC #6 lock #21):
//   coordinate (github.com/<owner>[/<repo>]) → register the repo: creating the
//     vault IS the consent that lets that repo's CI read it (grant under the hood)
//   free-form name → classic op:// container
const vaultCreateCommand = defineCommand({
  meta: { name: "create", description: "Create a vault — coordinate name (github.com/<owner>[/<repo>]) registers a repo for CI access; free-form name creates an op:// container" },
  args: {
    name: { type: "positional" as const, description: "Vault name", required: true },
    description: { type: "string" as const, description: "Vault description (op:// containers only)" },
    "ci-write": { type: "boolean" as const, description: "Let the repo's CI write its own project secrets (coordinate vaults only; default read-only)" },
    env: { type: "string" as const, description: "Narrow CI access to a GitHub environment (coordinate vaults only)" },
    ref: { type: "string" as const, description: "Narrow CI access to a git ref (coordinate vaults only)" },
    ...formatFlag,
  },
  async run({ args }) {
    const coord = parseVaultCoordinate(args.name)
    if (coord) {
      const coordName = `${coord.provider}/${coord.owner}${coord.repo ? `/${coord.repo}` : ""}`
      // The coordinate vault is a real op:// vault — it stores the secrets
      // (items). Create it idempotently; secrets are written with
      // `cvlt item create --vault <coordinate>`.
      const existing = (await api<Vault[]>("/v1/vaults")).find((v) => v.name.toLowerCase() === coordName)
      const vault = existing ?? (await api<Vault>("/v1/vaults", { method: "POST", body: { name: coordName, description: "" } }))

      // A repo coordinate also gets an OIDC grant (the consent that lets that
      // repo's CI read it). Grants are org-scoped, so this needs --org.
      type Grant = { id: string; repository: string; role: string }
      let grant: Grant | undefined
      const { org } = await getConfig()
      if (coord.repo && org) {
        const body: Record<string, unknown> = {
          repository: `${coord.owner}/${coord.repo}`,
          role: args["ci-write"] ? "write" : "read",
        }
        if (args.env) body.environment = args.env
        if (args.ref) body.ref = args.ref
        grant = await api<Grant>("/v1/oidc/grants", { method: "POST", body })
      }

      const lines = [
        `Vault: ${coordName} (${vault.id})`,
        `Write secrets with: cvlt item create --vault ${coordName} --title <NAME> 'value[password]=...'`,
      ]
      if (coord.repo && grant) {
        lines.push(`CI access registered (${grant.role}) — its CI can read vlt://${coordName}#<NAME> and owner globals.`)
      } else if (coord.repo) {
        lines.push(`(No CI grant created — pass --org ${coord.owner} to register this repo's CI access.)`)
      }
      await printMutation({ vault, grant: grant ?? null }, args.format, lines)
      return
    }

    const vault = await api<Vault>("/v1/vaults", {
      method: "POST",
      body: { name: args.name, description: args.description || "" },
    })
    await printMutation(vault, args.format, [`ID:   ${vault.id}`, `Name: ${vault.name}`])
  },
})

// vault edit
const vaultEditCommand = defineCommand({
  meta: { name: "edit", description: "Edit a vault" },
  args: {
    vault: { type: "positional" as const, description: "Vault name or ID", required: true },
    name: { type: "string" as const, description: "New vault name" },
    description: { type: "string" as const, description: "New description" },
    ...formatFlag,
  },
  async run({ args }) {
    const vaultId = await resolveVault(args.vault)
    const body: Record<string, string> = {}
    if (args.name) body.name = args.name
    if (args.description) body.description = args.description
    const vault = await api<Vault>(`/v1/vaults/${vaultId}`, { method: "PUT", body })
    await printMutation(vault, args.format, [`ID:   ${vault.id}`, `Name: ${vault.name}`])
  },
})

// vault delete — coordinate name revokes the repo's CI access (its secrets remain)
const vaultDeleteCommand = defineCommand({
  meta: { name: "delete", description: "Delete a vault (coordinate name revokes the repo's CI access; secrets remain)" },
  args: {
    vault: { type: "positional" as const, description: "Vault name or ID", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const coord = parseVaultCoordinate(args.vault)
    if (coord) {
      if (!coord.repo) {
        console.error("[ERROR] Owner-global has no registration to revoke. Delete individual items with 'cvlt item delete --vault <coordinate>'.")
        process.exit(1)
      }
      type Grant = { id: string; repository: string }
      const grants = await api<Grant[]>("/v1/oidc/grants")
      const matching = grants.filter((g) => g.repository.toLowerCase() === `${coord.owner}/${coord.repo}`)
      if (matching.length === 0) {
        console.error(`[ERROR] ${args.vault} is not registered`)
        process.exit(1)
      }
      for (const g of matching) {
        await api(`/v1/oidc/grants/${g.id}`, { method: "DELETE" })
      }
      await printMutation(
        { deleted: true, coordinate: args.vault, registrations: matching.length },
        args.format,
        [
          `Revoked CI access for ${args.vault} (${matching.length} registration${matching.length > 1 ? "s" : ""}).`,
          "Its secrets remain — remove them with 'cvlt item delete --vault <coordinate>' if needed.",
        ]
      )
      return
    }
    const vaultId = await resolveVault(args.vault)
    await api(`/v1/vaults/${vaultId}`, { method: "DELETE" })
    await printMutation(
      { deleted: true, vault: args.vault, vault_id: vaultId },
      args.format,
      [`Vault "${args.vault}" deleted.`]
    )
  },
})

const vaultCommand = defineCommand({
  meta: { name: "vault", description: "Manage vaults" },
  subCommands: {
    list: vaultListCommand,
    get: vaultGetCommand,
    create: vaultCreateCommand,
    edit: vaultEditCommand,
    delete: vaultDeleteCommand,
  },
})

// item list
const itemListCommand = defineCommand({
  meta: { name: "list", description: "List items in a vault" },
  args: {
    ...vaultFlag, ...formatFlag,
    tags: { type: "string" as const, description: "Filter by tags (comma-separated)" },
    categories: { type: "string" as const, description: "Filter by categories (comma-separated)" },
  },
  async run({ args }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const vaultId = await resolveVault(args.vault)
    const params = new URLSearchParams()
    if (args.tags) params.set("tags", args.tags)
    if (args.categories) params.set("categories", args.categories)
    const qs = params.toString() ? `?${params}` : ""
    const items = await api<Item[]>(`/v1/vaults/${vaultId}/items${qs}`)
    if (args.format === "json") {
      console.log(JSON.stringify(items, null, 2))
    } else {
      console.log(`${"ID".padEnd(28)} ${"TITLE".padEnd(30)} CATEGORY`)
      console.log("─".repeat(70))
      for (const item of items) {
        console.log(`${item.id.padEnd(28)} ${item.title.padEnd(30)} ${item.category}`)
      }
    }
  },
})

// item get
const itemGetCommand = defineCommand({
  meta: { name: "get", description: "Get item details" },
  args: {
    item: { type: "positional" as const, description: "Item name or ID", required: true },
    ...vaultFlag,
    ...formatFlag,
    reveal: { type: "boolean" as const, description: "Don't conceal sensitive fields" },
    fields: { type: "string" as const, description: "Return specific fields (comma-separated)" },
    otp: { type: "boolean" as const, description: "Output one-time password" },
  },
  async run({ args }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const vaultId = await resolveVault(args.vault)
    const itemId = await resolveItem(vaultId, args.item)
    const item = await api<Item>(`/v1/vaults/${vaultId}/items/${itemId}`)

    if (args.fields) {
      const specs = args.fields.split(",").map((f) => f.trim())
      const matched = item.fields?.filter((f) => {
        return specs.some((spec) => {
          if (spec.startsWith("label=")) return f.label === spec.slice(6)
          if (spec.startsWith("type=")) return f.type.toLowerCase() === spec.slice(5).toLowerCase()
          return f.label === spec // bare label
        })
      }) || []
      if (args.format === "json") {
        console.log(JSON.stringify(matched, null, 2))
      } else {
        for (const f of matched) {
          const val = !args.reveal && f.type === "CONCEALED" ? "••••••••" : f.value
          console.log(`${f.label}: ${val}`)
        }
      }
      return
    }

    if (args.format === "json") {
      console.log(JSON.stringify(item, null, 2))
    } else {
      console.log(`ID:       ${item.id}`)
      console.log(`Title:    ${item.title}`)
      console.log(`Category: ${item.category}`)
      console.log(`Vault:    ${item.vault.id}`)
      console.log(`Version:  ${item.version}`)
      if (item.urls?.length) console.log(`URL:      ${item.urls[0]!.href}`)
      if (item.fields?.length) {
        console.log(`\nFields:`)
        for (const f of item.fields) {
          const val = !args.reveal && f.type === "CONCEALED" ? "••••••••" : f.value
          console.log(`  ${f.label}: ${val}`)
        }
      }
    }
  },
})

// item create
const itemCreateCommand = defineCommand({
  meta: { name: "create", description: "Create a new item" },
  args: {
    ...vaultFlag,
    ...formatFlag,
    category: { type: "string" as const, description: "Item category (login, password, api_credential, secure_note, etc.)" },
    title: { type: "string" as const, description: "Item title" },
    url: { type: "string" as const, description: "URL for the item" },
    tags: { type: "string" as const, description: "Comma-separated tags" },
    favorite: { type: "boolean" as const, description: "Mark as favorite" },
    "generate-password": { type: "string" as const, description: "Generate a random password" },
  },
  async run({ args, rawArgs }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const vaultId = await resolveVault(args.vault)

    // Check for stdin template (op item create ... -)
    let templateFields: object[] = []
    if (rawArgs.includes("-")) {
      const chunks: Buffer[] = []
      for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
      const tpl = JSON.parse(Buffer.concat(chunks).toString("utf-8"))
      templateFields = tpl.fields || []
    }

    // Parse assignment args (positional args after flags)
    const assignments = rawArgs.filter((a) => a.includes("=") && !a.startsWith("--") && a !== "-")
    const fields = [...templateFields as any[], ...assignments.map((a) => {
      const parsed = parseFieldAssignment(a)
      const purpose = ["username", "password"].includes(parsed.label.toLowerCase())
        ? parsed.label.toUpperCase()
        : undefined
      const type = parsed.label.toLowerCase() === "password"
        ? "CONCEALED"
        : parsed.type ?? "STRING"
      return { id: parsed.label, label: parsed.label, value: parsed.value, type, purpose }
    })]

    // Override template fields with assignments
    for (const assign of assignments) {
      const parsed = parseFieldAssignment(assign)
      const existing = fields.findIndex((f: any) => f.label === parsed.label || f.id === parsed.label)
      if (existing >= 0) {
        (fields[existing] as any).value = parsed.value
      }
    }

    // Generate password if requested
    if (args["generate-password"] !== undefined) {
      const len = parseInt(args["generate-password"]) || 32
      const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@.-_*"
      const bytes = new Uint8Array(len)
      crypto.getRandomValues(bytes)
      const password = Array.from(bytes, (b) => charset[b % charset.length]).join("")
      fields.push({ id: "password", label: "password", value: password, type: "CONCEALED", purpose: "PASSWORD" })
    }

    const urls = args.url ? [{ primary: true, href: args.url }] : []
    const tags = args.tags ? args.tags.split(",").map((t) => t.trim()) : []

    const item = await api<Item>(`/v1/vaults/${vaultId}/items`, {
      method: "POST",
      body: {
        title: args.title || "Untitled",
        category: (args.category || "LOGIN").toUpperCase(),
        fields,
        urls,
        tags,
        favorite: args.favorite || false,
      },
    })

    await printMutation(item, args.format, [
      `ID:    ${item.id}`,
      `Title: ${item.title}`,
      `Vault: ${item.vault.id}`,
    ])
  },
})

// item edit
const itemEditCommand = defineCommand({
  meta: { name: "edit", description: "Edit an item" },
  args: {
    item: { type: "positional" as const, description: "Item name or ID", required: true },
    ...vaultFlag,
    ...formatFlag,
    title: { type: "string" as const, description: "New title" },
  },
  async run({ args, rawArgs }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const vaultId = await resolveVault(args.vault)
    const itemId = await resolveItem(vaultId, args.item)

    // Get current item
    const current = await api<Item>(`/v1/vaults/${vaultId}/items/${itemId}`)

    // Parse assignment args for field updates
    const assignments = rawArgs.filter(isFieldAssignment)
    const updatedFields = applyFieldAssignments(current.fields || [], assignments)

    const item = await api<Item>(`/v1/vaults/${vaultId}/items/${itemId}`, {
      method: "PUT",
      body: {
        title: args.title ?? current.title,
        category: current.category,
        fields: updatedFields,
        sections: current.sections,
        urls: current.urls,
        tags: current.tags,
        favorite: current.favorite,
      },
    })

    await printMutation(item, args.format, [
      `ID:      ${item.id}`,
      `Title:   ${item.title}`,
      `Version: ${item.version}`,
    ])
  },
})

// item delete
const itemDeleteCommand = defineCommand({
  meta: { name: "delete", description: "Delete an item" },
  args: {
    item: { type: "positional" as const, description: "Item name or ID", required: true },
    ...vaultFlag,
    ...formatFlag,
  },
  async run({ args }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const vaultId = await resolveVault(args.vault)
    const itemId = await resolveItem(vaultId, args.item)
    await api(`/v1/vaults/${vaultId}/items/${itemId}`, { method: "DELETE" })
    await printMutation(
      { deleted: true, item: args.item, item_id: itemId, vault_id: vaultId },
      args.format,
      [`Item "${args.item}" deleted.`]
    )
  },
})

// item template (client-side, matches op item template output)
const ITEM_TEMPLATES: Record<string, { title: string; category: string; fields: object[] }> = {
  LOGIN: {
    title: "", category: "LOGIN",
    fields: [
      { id: "username", type: "STRING", purpose: "USERNAME", label: "username", value: "" },
      { id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: "" },
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
    ],
  },
  PASSWORD: {
    title: "", category: "PASSWORD",
    fields: [
      { id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: "" },
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
    ],
  },
  API_CREDENTIAL: {
    title: "", category: "API_CREDENTIAL",
    fields: [
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
      { id: "username", type: "STRING", label: "username", value: "" },
      { id: "credential", type: "CONCEALED", label: "credential", value: "" },
      { id: "type", type: "MENU", label: "type", value: "" },
      { id: "filename", type: "STRING", label: "filename", value: "" },
      { id: "validFrom", type: "DATE", label: "valid from", value: "" },
      { id: "expires", type: "DATE", label: "expires", value: "" },
      { id: "hostname", type: "STRING", label: "hostname", value: "" },
    ],
  },
  SECURE_NOTE: {
    title: "", category: "SECURE_NOTE",
    fields: [
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
    ],
  },
  DATABASE: {
    title: "", category: "DATABASE",
    fields: [
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
      { id: "database_type", type: "MENU", label: "type", value: "" },
      { id: "hostname", type: "STRING", label: "server", value: "" },
      { id: "port", type: "STRING", label: "port", value: "" },
      { id: "database", type: "STRING", label: "database", value: "" },
      { id: "username", type: "STRING", label: "username", value: "" },
      { id: "password", type: "CONCEALED", label: "password", value: "" },
      { id: "sid", type: "STRING", label: "SID", value: "" },
      { id: "alias", type: "STRING", label: "alias", value: "" },
      { id: "options", type: "STRING", label: "connection options", value: "" },
    ],
  },
  SERVER: {
    title: "", category: "SERVER",
    fields: [
      { id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain", value: "" },
      { id: "url", type: "STRING", label: "URL", value: "" },
      { id: "username", type: "STRING", label: "username", value: "" },
      { id: "password", type: "CONCEALED", label: "password", value: "" },
    ],
  },
}

const TEMPLATE_LIST = [
  { uuid: "001", name: "Login" },
  { uuid: "002", name: "Credit Card" },
  { uuid: "003", name: "Secure Note" },
  { uuid: "004", name: "Identity" },
  { uuid: "005", name: "Password" },
  { uuid: "006", name: "Document" },
  { uuid: "100", name: "Software License" },
  { uuid: "101", name: "Bank Account" },
  { uuid: "102", name: "Database" },
  { uuid: "103", name: "Driver License" },
  { uuid: "104", name: "Outdoor License" },
  { uuid: "105", name: "Membership" },
  { uuid: "106", name: "Passport" },
  { uuid: "107", name: "Reward Program" },
  { uuid: "108", name: "Social Security Number" },
  { uuid: "109", name: "Wireless Router" },
  { uuid: "110", name: "Server" },
  { uuid: "111", name: "Email Account" },
  { uuid: "112", name: "API Credential" },
  { uuid: "113", name: "Medical Record" },
  { uuid: "114", name: "SSH Key" },
  { uuid: "115", name: "Crypto Wallet" },
]

const itemTemplateListCommand = defineCommand({
  meta: { name: "list", description: "List item templates" },
  args: { ...formatFlag },
  run({ args }) {
    if (args.format === "json") {
      console.log(JSON.stringify(TEMPLATE_LIST, null, 2))
    } else {
      console.log(`${"UUID".padEnd(6)} NAME`)
      console.log("─".repeat(30))
      for (const t of TEMPLATE_LIST) {
        console.log(`${t.uuid.padEnd(6)} ${t.name}`)
      }
    }
  },
})

const itemTemplateGetCommand = defineCommand({
  meta: { name: "get", description: "Get an item template" },
  args: {
    category: { type: "positional" as const, description: "Category name", required: true },
    ...formatFlag,
  },
  run({ args }) {
    const key = args.category.toUpperCase().replace(/ /g, "_")
    const template = ITEM_TEMPLATES[key]
    if (!template) {
      console.error(`[ERROR] Unknown category: ${args.category}`)
      console.error(`Available: ${Object.keys(ITEM_TEMPLATES).join(", ")}`)
      process.exit(1)
    }
    console.log(JSON.stringify(template, null, 2))
  },
})

const itemTemplateCommand = defineCommand({
  meta: { name: "template", description: "Manage item templates" },
  subCommands: {
    list: itemTemplateListCommand,
    get: itemTemplateGetCommand,
  },
})

// item move
const itemMoveCommand = defineCommand({
  meta: { name: "move", description: "Move an item between vaults" },
  args: {
    item: { type: "positional" as const, description: "Item name or ID", required: true },
    "current-vault": { type: "string" as const, description: "Source vault", required: true },
    "destination-vault": { type: "string" as const, description: "Destination vault", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const srcVaultId = await resolveVault(args["current-vault"]!)
    const destVaultId = await resolveVault(args["destination-vault"]!)
    const itemId = await resolveItem(srcVaultId, args.item)
    const item = await api<Item>(`/v1/vaults/${srcVaultId}/items/${itemId}/move`, {
      method: "POST",
      body: { vault: destVaultId },
    })
    await printMutation(item, args.format, [
      `Item "${args.item}" moved to vault "${args["destination-vault"]}".`,
    ])
  },
})

const itemCommand = defineCommand({
  meta: { name: "item", description: "Manage items in your vaults" },
  subCommands: {
    list: itemListCommand,
    get: itemGetCommand,
    create: itemCreateCommand,
    edit: itemEditCommand,
    delete: itemDeleteCommand,
    move: itemMoveCommand,
    template: itemTemplateCommand,
  },
})

// document create
const documentCreateCommand = defineCommand({
  meta: { name: "create", description: "Upload a document" },
  args: {
    file: { type: "positional" as const, description: "File path", required: true },
    ...vaultFlag,
    title: { type: "string" as const, description: "Document title" },
    ...formatFlag,
  },
  async run({ args }) {
    if (!args.vault) { console.error("[ERROR] --vault is required"); process.exit(1) }
    const vaultId = await resolveVault(args.vault)

    // Create a LOGIN item to hold the document reference, then upload file
    const title = args.title || args.file.split("/").pop() || "Document"
    const item = await api<Item>(`/v1/vaults/${vaultId}/items`, {
      method: "POST",
      body: { title, category: "DOCUMENT", fields: [] },
    })

    const fileContent = readFileSync(args.file)
    await uploadFile(
      vaultId,
      item.id,
      args.file.split("/").pop() || "file",
      "application/octet-stream",
      new Uint8Array(fileContent)
    )

    await printMutation(
      { id: item.id, title, vault_id: vaultId },
      args.format,
      [`ID:    ${item.id}`, `Title: ${title}`]
    )
  },
})

// document list
const documentListCommand = defineCommand({
  meta: { name: "list", description: "List documents" },
  args: { ...vaultFlag, ...formatFlag },
  async run({ args }) {
    if (!args.vault) { console.error("[ERROR] --vault is required"); process.exit(1) }
    const vaultId = await resolveVault(args.vault)
    const items = await api<Item[]>(`/v1/vaults/${vaultId}/items`)
    const docs = items.filter((i) => i.category === "DOCUMENT")
    if (args.format === "json") {
      console.log(JSON.stringify(docs, null, 2))
    } else {
      console.log(`${"ID".padEnd(28)} TITLE`)
      console.log("─".repeat(50))
      for (const d of docs) console.log(`${d.id.padEnd(28)} ${d.title}`)
    }
  },
})

// document get (download)
const documentGetCommand = defineCommand({
  meta: { name: "get", description: "Download a document" },
  args: {
    document: { type: "positional" as const, description: "Document name or ID", required: true },
    ...vaultFlag,
    output: { type: "string" as const, alias: "o", description: "Output file path" },
  },
  async run({ args }) {
    if (!args.vault) { console.error("[ERROR] --vault is required"); process.exit(1) }
    const vaultId = await resolveVault(args.vault)
    const itemId = await resolveItem(vaultId, args.document)
    type FileInfo = { id: string; name: string; size: number; content_path: string }
    const fileList = await api<FileInfo[]>(`/v1/vaults/${vaultId}/items/${itemId}/files`)
    if (fileList.length === 0) {
      console.error("[ERROR] No files attached to this document")
      process.exit(1)
    }
    const file = fileList[0]!
    const downloaded = await downloadFile(vaultId, itemId, file.id)
    const content = Buffer.from(downloaded.content)
    if (args.output) {
      writeFileSync(args.output, content)
      console.log(`Saved to ${args.output}`)
    } else {
      process.stdout.write(content)
    }
  },
})

const documentCommand = defineCommand({
  meta: { name: "document", description: "Manage documents" },
  subCommands: {
    create: documentCreateCommand,
    list: documentListCommand,
    get: documentGetCommand,
  },
})

// whoami
const whoamiCommand = defineCommand({
  meta: { name: "whoami", description: "Show connection info" },
  async run() {
    const { baseUrl, org } = await getConfig()
    console.log(`Host:    ${baseUrl}`)
    console.log(`Account: ${org ? `org:${org}` : "personal"}`)
  },
})

const authTokenCommand = defineCommand({
  meta: { name: "token", description: "Print the selected profile's Circles access token" },
  async run() {
    console.log(await getCirclesToken())
  },
})

const authCommand = defineCommand({
  meta: { name: "auth", description: "Authentication utilities" },
  subCommands: { token: authTokenCommand },
})

// ── OIDC grants ─────────────────────────────────────────────────────────────

type Grant = {
  id: string
  provider: string
  repository: string
  environment?: string
  ref?: string
  vault_id?: string
  role: "read" | "write"
  created_at: string
  updated_at: string
}

function printGrantsTable(grants: Grant[]) {
  if (grants.length === 0) {
    console.log("(no grants)")
    return
  }
  console.log(
    `${"ID".padEnd(28)} ${"REPOSITORY".padEnd(32)} ${"ENV".padEnd(12)} ${"REF".padEnd(20)} ${"VAULT".padEnd(28)} ROLE`
  )
  console.log("─".repeat(130))
  for (const g of grants) {
    console.log(
      `${g.id.padEnd(28)} ${g.repository.padEnd(32)} ${(g.environment ?? "—").padEnd(12)} ${(g.ref ?? "—").padEnd(20)} ${(g.vault_id ?? "—").padEnd(28)} ${g.role}`
    )
  }
}

// oidc grant list
const oidcGrantListCommand = defineCommand({
  meta: { name: "list", description: "List OIDC grants in this org" },
  args: { ...formatFlag },
  async run({ args }) {
    const grants = await api<Grant[]>("/v1/oidc/grants")
    if (args.format === "json") {
      console.log(JSON.stringify(grants, null, 2))
    } else {
      printGrantsTable(grants)
    }
  },
})

// oidc grant get
const oidcGrantGetCommand = defineCommand({
  meta: { name: "get", description: "Get one OIDC grant by ID" },
  args: {
    id: { type: "positional" as const, description: "Grant ID", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const grant = await api<Grant>(`/v1/oidc/grants/${args.id}`)
    if (args.format === "json") {
      console.log(JSON.stringify(grant, null, 2))
    } else {
      console.log(`ID:         ${grant.id}`)
      console.log(`Repository: ${grant.repository}`)
      if (grant.environment) console.log(`Env:        ${grant.environment}`)
      if (grant.ref) console.log(`Ref:        ${grant.ref}`)
      if (grant.vault_id) console.log(`Vault:      ${grant.vault_id}`)
      console.log(`Role:       ${grant.role}`)
      console.log(`Created:    ${grant.created_at}`)
      console.log(`Updated:    ${grant.updated_at}`)
    }
  },
})

const grantBodyFlags = {
  role: { type: "string" as const, description: "read | write (default: read)" },
  env: { type: "string" as const, description: "Optional environment (e.g. production)" },
  ref: { type: "string" as const, description: "Optional ref (e.g. refs/heads/main)" },
  vault: { type: "string" as const, description: "Optional vault name or ID; omit for org-wide grant" },
  ...formatFlag,
}

async function resolveOptionalVault(name: string | undefined): Promise<string | undefined> {
  if (!name) return undefined
  return resolveVault(name)
}

// oidc grant create
const oidcGrantCreateCommand = defineCommand({
  meta: { name: "create", description: "Create an OIDC grant for a GitHub repository" },
  args: {
    repository: {
      type: "positional" as const,
      description: "GitHub repository in 'owner/repo' format",
      required: true,
    },
    ...grantBodyFlags,
  },
  async run({ args }) {
    const body: Record<string, unknown> = { repository: args.repository }
    if (args.role) body.role = args.role
    if (args.env) body.environment = args.env
    if (args.ref) body.ref = args.ref
    if (args.vault) body.vault_id = await resolveOptionalVault(args.vault)
    const grant = await api<Grant>("/v1/oidc/grants", { method: "POST", body })
    await printMutation(grant, args.format, [
      `Created grant ${grant.id} for ${grant.repository} (${grant.role})`,
    ])
  },
})

// oidc grant edit
const oidcGrantEditCommand = defineCommand({
  meta: { name: "edit", description: "Update an OIDC grant. Pass 'null' to clear an optional field." },
  args: {
    id: { type: "positional" as const, description: "Grant ID", required: true },
    repository: { type: "string" as const, description: "New repository value" },
    ...grantBodyFlags,
  },
  async run({ args }) {
    const body: Record<string, unknown> = {}
    if (args.repository) body.repository = args.repository
    if (args.role) body.role = args.role
    // For env/ref/vault, "null" string sentinel clears the field
    if (args.env !== undefined) body.environment = args.env === "null" ? null : args.env
    if (args.ref !== undefined) body.ref = args.ref === "null" ? null : args.ref
    if (args.vault !== undefined) {
      body.vault_id = args.vault === "null" ? null : await resolveOptionalVault(args.vault)
    }
    const grant = await api<Grant>(`/v1/oidc/grants/${args.id}`, { method: "PUT", body })
    await printMutation(grant, args.format, [`Updated grant ${grant.id}`])
  },
})

// oidc grant delete
const oidcGrantDeleteCommand = defineCommand({
  meta: { name: "delete", description: "Revoke an OIDC grant" },
  args: {
    id: { type: "positional" as const, description: "Grant ID", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    await api(`/v1/oidc/grants/${args.id}`, { method: "DELETE" })
    await printMutation(
      { deleted: true, grant_id: args.id },
      args.format,
      [`Deleted grant ${args.id}`]
    )
  },
})

const oidcGrantCommand = defineCommand({
  meta: { name: "grant", description: "Manage OIDC grants" },
  subCommands: {
    list: oidcGrantListCommand,
    get: oidcGrantGetCommand,
    create: oidcGrantCreateCommand,
    edit: oidcGrantEditCommand,
    delete: oidcGrantDeleteCommand,
  },
})

// 'cvlt vault create github.com/<owner>/<repo>' is the primary registration
// path (RFC #6 lock #21); these advanced commands support explicit grant
// scoping and narrowing existing registrations.
const oidcCommand = defineCommand({
  meta: { name: "oidc", description: "Advanced OIDC grant management" },
  subCommands: {
    grant: oidcGrantCommand,
  },
})

const doctorCommand = defineCommand({
  meta: { name: "doctor", description: "Check client encryption state" },
  args: { ...formatFlag },
  async run({ args }) {
    const status = await doctorE2ee()
    if (args.format === "json") {
      console.log(JSON.stringify(status, null, 2))
      return
    }
    console.log(`Account encryption: ${status.initialized ? "ready" : "not initialized"}`)
    console.log(`Local client key:   ${status.client_registered ? "registered" : "not registered"}`)
    console.log(`Vaults:             ${status.vaults} encrypted`)
    console.log(`Items:              ${status.items} encrypted`)
    console.log(`GitHub OIDC KMS:    ${status.kms_ready ? "ready" : "not ready"}`)
  },
})

const recoveryStartCommand = defineCommand({
  meta: { name: "start", description: "Send an account recovery verification code" },
  async run() {
    await startRecovery()
    console.log("If recovery is available, a verification code will be sent.")
  },
})

const recoveryCompleteCommand = defineCommand({
  meta: { name: "complete", description: "Register this installation using recovery" },
  args: {
    code: { type: "positional" as const, description: "8-digit email verification code", required: true },
  },
  async run({ args }) {
    await completeRecovery(args.code, promptSecret("Vault recovery code: "))
    console.log("This installation is registered and can decrypt the account.")
  },
})

const recoverCommand = defineCommand({
  meta: { name: "recover", description: "Recover access on a new installation" },
  subCommands: {
    start: recoveryStartCommand,
    complete: recoveryCompleteCommand,
  },
})

// ── Client installations ────────────────────────────────────────────────────
// Enrollment lets a second PC join an account without the destructive recovery
// path. stdout carries only the data surface (the enrollment token, the JSON
// document, or the result); prompts and diagnostics go to stderr.

function note(line: string) {
  process.stderr.write(`${line}\n`)
}

const clientRequestCommand = defineCommand({
  meta: {
    name: "request",
    description: "Print a public enrollment request for this installation",
  },
  args: {
    name: { type: "string" as const, description: "Display name for this installation (max 64 characters)" },
    ...formatFlag,
  },
  async run({ args }) {
    const result = await requestClientEnrollment(args.name)
    if (result.status === "already-registered") {
      note(`This installation is already registered to ${result.account} at ${result.origin}.`)
      note(`Fingerprint:  ${result.fingerprint}`)
      note("Nothing to enroll. Run cvlt doctor to check its encryption state.")
      if (args.format === "json") console.log(JSON.stringify(result, null, 2))
      return
    }
    note(`Vault origin: ${result.origin}`)
    note(`Account:      ${result.account}`)
    note(`Platform:     ${result.platform}`)
    note(`Name:         ${result.name ?? "(none)"}`)
    note(`Fingerprint:  ${result.fingerprint}`)
    note(
      result.created_key
        ? "Generated this Vault origin's installation key."
        : "Reused this Vault origin's existing installation key."
    )
    note("")
    note("On an already registered installation, run 'cvlt client approve <request>'")
    note("and check that it shows the same fingerprint.")
    note("")
    if (args.format === "json") {
      console.log(JSON.stringify(result, null, 2))
      return
    }
    console.log(result.request)
  },
})

const clientApproveCommand = defineCommand({
  meta: {
    name: "approve",
    description: "Approve another installation's enrollment request",
  },
  args: {
    request: { type: "positional" as const, description: "Enrollment request from 'cvlt client request'", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const result = await approveClientEnrollment(args.request, (details) => {
      for (const line of approvalPreview(details)) note(line)
      return isAffirmative(promptLine("Type yes to approve: "))
    })
    if (result.status === "declined") {
      note("Declined. No installation was registered.")
      if (args.format === "json") console.log(JSON.stringify(result, null, 2))
      process.exit(1)
    }
    await printMutation({ approved: true, ...result.details }, args.format, [
      `Approved installation ${result.details.client_id}`,
      `Fingerprint: ${result.details.fingerprint}`,
      "It can now read this account. Confirm with 'cvlt client list'.",
    ])
  },
})

const clientListCommand = defineCommand({
  meta: { name: "list", description: "List active installations of this account" },
  args: { ...formatFlag },
  async run({ args }) {
    const clients = await listClients()
    if (args.format === "json") {
      console.log(JSON.stringify(clients, null, 2))
      return
    }
    for (const line of clientTable(clients)) console.log(line)
  },
})

const clientRevokeCommand = defineCommand({
  meta: { name: "revoke", description: "Revoke another installation of this account" },
  args: {
    client: { type: "positional" as const, description: "Client ID from 'cvlt client list'", required: true },
    ...formatFlag,
  },
  async run({ args }) {
    const result = await revokeClient(args.client)
    await printMutation({ revoked: true, ...result }, args.format, [
      `Revoked installation ${result.client_id}`,
      "It can no longer decrypt this account. Its Vault content is unchanged.",
    ])
  },
})

const clientCommand = defineCommand({
  meta: { name: "client", description: "Enroll and manage this account's installations" },
  subCommands: {
    request: clientRequestCommand,
    approve: clientApproveCommand,
    list: clientListCommand,
    revoke: clientRevokeCommand,
  },
})

const connectCommand = defineCommand({
  meta: { name: "connect", description: "Run a local 1Password Connect-compatible bridge" },
  args: {
    port: { type: "string" as const, description: "Local port (default: random)" },
  },
  async run({ args }) {
    const port = args.port === undefined ? 0 : Number(args.port)
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      console.error("[ERROR] --port must be between 0 and 65535")
      process.exit(1)
    }
    const bridge = await startConnectServer(port)
    console.log(`1Password Connect bridge listening on ${bridge.host}`)
    console.log(`export OP_CONNECT_HOST=${bridge.host}`)
    console.log(`export OP_CONNECT_TOKEN=${bridge.token}`)
    await new Promise<void>((resolve) => {
      const stop = () => {
        bridge.stop()
        resolve()
      }
      process.once("SIGINT", stop)
      process.once("SIGTERM", stop)
    })
  },
})

// ── import ──────────────────────────────────────────────────────────────────
// Parse a .env file into KEY/value pairs. Handles `export ` prefix, `#` comments,
// blank lines, and single/double-quoted values (with \n / \" escapes in "..").
function parseDotenv(text: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = []
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim()
    if (!line || line.startsWith("#")) continue
    if (line.startsWith("export ")) line = line.slice(7).trimStart()
    const eq = line.indexOf("=")
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue
    let value = line.slice(eq + 1).trim()
    if (
      value.length >= 2 &&
      ((value[0] === '"' && value.at(-1) === '"') || (value[0] === "'" && value.at(-1) === "'"))
    ) {
      const quote = value[0]
      value = value.slice(1, -1)
      if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"')
    }
    out.push({ key, value })
  }
  return out
}

const importCommand = defineCommand({
  meta: {
    name: "import",
    description: "Import KEY=value pairs from a .env file into a vault as flat secrets",
  },
  args: {
    file: { type: "positional" as const, description: ".env file path", required: true },
    ...vaultFlag,
    ...formatFlag,
    prefix: { type: "string" as const, description: "Prefix prepended to each key (item title)" },
    "skip-existing": {
      type: "boolean" as const,
      description: "Skip keys that already exist (default: overwrite)",
    },
    "dry-run": { type: "boolean" as const, description: "Preview without writing" },
  },
  async run({ args }) {
    if (!args.vault) {
      console.error("[ERROR] --vault is required")
      process.exit(1)
    }
    const entries = parseDotenv(readFileSync(args.file as string, "utf-8"))
    if (entries.length === 0) {
      console.log("No KEY=value pairs found.")
      return
    }
    const vaultId = await resolveVault(args.vault)
    let created = 0
    let overwritten = 0
    let skipped = 0
    const actions: { action: "create" | "overwrite"; title: string }[] = []
    for (const { key, value } of entries) {
      const title = `${args.prefix ?? ""}${key}`
      // A flat secret is a single field whose id is "value" — that's what the
      // vlt:// / op:// resolver reads back (read.ts extractValue).
      const fields = [{ id: "value", label: "value", value, type: "CONCEALED", purpose: "PASSWORD" }]
      const existing = await api<{ id: string }[]>(
        `/v1/vaults/${vaultId}/items?filter=${encodeURIComponent(`title eq "${title}"`)}`
      )
      if (args["dry-run"]) {
        actions.push({ action: existing.length ? "overwrite" : "create", title })
        continue
      }
      if (existing.length > 0) {
        if (args["skip-existing"]) {
          skipped++
          continue
        }
        await api(`/v1/vaults/${vaultId}/items/${existing[0]!.id}`, {
          method: "PUT",
          body: { title, category: "API_CREDENTIAL", fields },
        })
        overwritten++
      } else {
        await api(`/v1/vaults/${vaultId}/items`, {
          method: "POST",
          body: { title, category: "API_CREDENTIAL", fields, urls: [], tags: [], favorite: false },
        })
        created++
      }
    }
    if (args["dry-run"]) {
      await printMutation(
        { dry_run: true, vault: args.vault, actions },
        args.format,
        actions.map(({ action, title }) => `${action}  ${title}`)
      )
      return
    }
    await printMutation(
      { vault: args.vault, created, overwritten, skipped },
      args.format,
      [`Imported into ${args.vault}: ${created} created, ${overwritten} overwritten, ${skipped} skipped`]
    )
  },
})

// ── Main ────────────────────────────────────────────────────────────────────

export const main = defineCommand({
  meta: {
    name: "cvlt",
    description: "1Password-style secrets CLI for Circles Vault",
    version: (pkg as { version?: string }).version || "dev",
  },
  args: {
    profile: { type: "string" as const, description: "Circles profile to use (default: shared current profile)" },
    org: { type: "string" as const, description: "Target an org account. vlt:// reads infer an accessible owner org; other commands default to personal. Also honors CRCL_ORG." },
  },
  setup({ args }) {
    setOverrides({ profile: args.profile, org: args.org })
  },
  subCommands: {
    auth: authCommand,
    read: readCommand,
    inject: injectCommand,
    run: runCommand,
    import: importCommand,
    vault: vaultCommand,
    item: itemCommand,
    document: documentCommand,
    oidc: oidcCommand,
    doctor: doctorCommand,
    client: clientCommand,
    recover: recoverCommand,
    connect: connectCommand,
    whoami: whoamiCommand,
  },
})

if (import.meta.main) {
  await checkForUpdate()
  runMain(main)
}
