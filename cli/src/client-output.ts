import { formatFingerprint, type ClientSummary, type EnrollmentApprovalDetails } from "@circlesac/vault/cli"

const TERMINAL_CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu

/** Only an unambiguous yes approves an enrollment. Anything else declines. */
export function isAffirmative(answer: string): boolean {
  return ["y", "yes"].includes(answer.trim().toLowerCase())
}

/**
 * What the approving installation sees before it confirms. The fingerprint
 * here must match the one the requesting installation printed.
 */
export function approvalPreview(details: EnrollmentApprovalDetails): string[] {
  return [
    "Approve this installation?",
    `  Vault origin: ${details.origin}`,
    `  Account:      ${details.account}`,
    `  Name:         ${details.name ?? "(none)"}`,
    `  Platform:     ${details.platform}`,
    `  Fingerprint:  ${details.fingerprint}`,
    "",
    "The fingerprint must match the one shown on the requesting machine.",
  ]
}

/** Keep legacy server metadata from injecting terminal controls or stretching
 * the human table without bound. JSON output remains the original structure. */
function terminalCell(value: string | null, width: number): string {
  const cleaned = (value ?? "—").replace(TERMINAL_CONTROL_RE, "?")
  const characters = Array.from(cleaned)
  const bounded = characters.length > width
    ? `${characters.slice(0, Math.max(0, width - 1)).join("")}…`
    : cleaned
  return bounded.padEnd(width)
}

function terminalText(value: string, maximum: number): string {
  const cleaned = value.replace(TERMINAL_CONTROL_RE, "?")
  const characters = Array.from(cleaned)
  return characters.length > maximum
    ? `${characters.slice(0, maximum - 1).join("")}…`
    : cleaned
}

export function clientTable(clients: ClientSummary[]): string[] {
  if (clients.length === 0) return ["(no active installations)"]
  const lines = [
    `${"CLIENT ID".padEnd(43)} ${"NAME".padEnd(20)} ${"PLATFORM".padEnd(10)} ${"CREATED".padEnd(24)} CURRENT`,
    "─".repeat(110),
  ]
  for (const client of clients) {
    lines.push(
      `${terminalCell(client.id, 43)} ${terminalCell(client.name, 20)} ${terminalCell(client.platform, 10)} ${terminalCell(client.created_at, 24)} ${client.is_current ? "yes" : "no"}`
    )
  }
  lines.push("")
  for (const client of clients) {
    lines.push(`${terminalText(formatFingerprint(client.id), 160)}${client.is_current ? "  (this installation)" : ""}`)
  }
  return lines
}
