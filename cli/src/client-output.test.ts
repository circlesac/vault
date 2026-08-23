import { describe, expect, it } from "bun:test"
import { approvalPreview, clientTable, isAffirmative } from "./client-output"

const clientId = "Ln7Qk2wA9xTvB0cRd4Fh6JmPq8SsUwYz1AeGiKoM3Nu"
const otherId = "Zx4Vb8Nm2Qw6Er0Ty1Ui3Op5As7Df9Gh1Jk3Lz5Cv7"

describe("approval preview", () => {
  it("shows everything the approver must compare", () => {
    const lines = approvalPreview({
      origin: "https://vault.crcl.es",
      account: "org:7",
      client_id: clientId,
      fingerprint: `SHA256:${clientId}`,
      platform: "linux",
      name: "example-workstation",
      current_client_id: otherId,
    })
    expect(lines).toEqual([
      "Approve this installation?",
      "  Vault origin: https://vault.crcl.es",
      "  Account:      org:7",
      "  Name:         example-workstation",
      "  Platform:     linux",
      `  Fingerprint:  SHA256:${clientId}`,
      "",
      "The fingerprint must match the one shown on the requesting machine.",
    ])
  })

  it("marks a missing display name instead of printing undefined", () => {
    const lines = approvalPreview({
      origin: "https://vault.circles.ac",
      account: "user:1",
      client_id: clientId,
      fingerprint: `SHA256:${clientId}`,
      platform: "darwin",
      name: null,
      current_client_id: otherId,
    })
    expect(lines).toContain("  Name:         (none)")
    expect(lines.join("\n")).not.toContain("undefined")
  })
})

describe("confirmation", () => {
  it("accepts only an unambiguous yes", () => {
    for (const answer of ["y", "Y", "yes", "YES", " Yes "]) expect(isAffirmative(answer)).toBe(true)
    for (const answer of ["", "n", "no", "ok", "sure", "yes please", "1"]) {
      expect(isAffirmative(answer)).toBe(false)
    }
  })
})

describe("client table", () => {
  it("marks the current installation and lists a fingerprint per row", () => {
    const lines = clientTable([
      { id: clientId, name: "approver", platform: "darwin", created_at: "2026-08-23T00:00:00Z", is_current: true },
      { id: otherId, name: null, platform: null, created_at: "2026-08-23T01:00:00Z", is_current: false },
    ])
    const table = lines.join("\n")
    expect(lines[0]).toContain("CLIENT ID")
    expect(table).toContain(clientId)
    expect(table).toContain(otherId)
    expect(table).toContain("(this installation)")
    expect(table).toContain("—")
    expect(table).not.toContain("null")
    expect(table).not.toContain("undefined")
  })

  it("says so when nothing is active", () => {
    expect(clientTable([])).toEqual(["(no active installations)"])
  })

  it("neutralizes terminal controls and bounds legacy metadata", () => {
    const table = clientTable([{
      id: clientId,
      name: `unsafe\u001b[31m\u202e${"x".repeat(80)}`,
      platform: "linux\nspoofed",
      created_at: "2026-08-23T00:00:00Z\rOVERWRITE",
      is_current: false,
    }]).join("\n")
    expect(table).not.toContain("\u001b")
    expect(table).not.toContain("\u202e")
    expect(table).not.toContain("linux\nspoofed")
    expect(table).not.toContain("\rOVERWRITE")
    expect(table).toContain("unsafe?[31m")
    expect(table).toContain("…")
  })
})
