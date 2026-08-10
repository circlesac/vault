import { describe, expect, it } from "bun:test"
import { mutationResult, mutationTarget, mutationTargetLine } from "./mutation-output"

describe("mutation output", () => {
  it("describes a personal production target", () => {
    const target = mutationTarget({ baseUrl: "https://vault.circles.ac", org: null })

    expect(target).toEqual({ account: "personal", host: "https://vault.circles.ac" })
    expect(mutationTargetLine(target)).toBe("Account: personal @ https://vault.circles.ac")
  })

  it("separates an organization account from the host", () => {
    const target = mutationTarget({
      baseUrl: "https://vault.circles.ac/circlesac",
      org: "circlesac",
    })

    expect(target).toEqual({ account: "org:circlesac", host: "https://vault.circles.ac" })
  })

  it("adds account and host to JSON results", () => {
    expect(
      mutationResult(
        { id: "item-1", title: "Example" },
        { account: "org:circlesac", host: "https://vault.circles.ac" }
      )
    ).toEqual({
      id: "item-1",
      title: "Example",
      account: "org:circlesac",
      host: "https://vault.circles.ac",
    })
  })
})
