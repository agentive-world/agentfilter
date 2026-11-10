/**
 * Plugin entry-point shape tests.
 *
 * OpenCode's plugin loader surface differs across versions (verified across
 * 1.3.3-2.2.5 in safedep/gryph#100):
 * - 1.x <= 1.3.3 calls the named export.
 * - 1.x 1.3.4+ calls default.server.
 * - 2.x calls default.setup, which registers hooks on their owning domain
 *   (e.g. ctx.tool.hook("execute.before")) and receives a payload of
 *   { tool, sessionID, id, input }.
 */

import { describe, it, expect } from "vitest"
import { SecurityFilterPlugin } from "../security-filter.js"
import agentfilter from "../security-filter.js"

describe("plugin entry points", () => {
  it("exposes the named export used by OpenCode 1.x <= 1.3.3", async () => {
    const hooks = await SecurityFilterPlugin({})
    expect(typeof hooks["tool.execute.before"]).toBe("function")
  })

  it("exposes default.server for OpenCode 1.x 1.3.4+", async () => {
    expect(typeof agentfilter.server).toBe("function")
    expect(agentfilter.server).toBe(SecurityFilterPlugin)
    const hooks = await agentfilter.server({})
    expect(typeof hooks["tool.execute.before"]).toBe("function")
  })

  it("exposes a default export with an id and a 2.x setup function", () => {
    expect(agentfilter.id).toBe("agentfilter")
    expect(typeof agentfilter.setup).toBe("function")
  })

  it("setup registers the V2 execute.before hook on ctx.tool", async () => {
    const registered = new Map<string, (event: unknown) => unknown>()
    await agentfilter.setup({
      tool: {
        hook: (name, fn) => {
          registered.set(name, fn)
        },
      },
    })
    expect([...registered.keys()]).toEqual(["execute.before"])
    expect(typeof registered.get("execute.before")).toBe("function")
  })

  it("adapts the V2 payload { tool, input } to the 1.x signature end to end", async () => {
    const registered = new Map<string, (event: unknown) => unknown>()
    await agentfilter.setup({
      tool: {
        hook: (name, fn) => {
          registered.set(name, fn)
        },
      },
    })
    const before = registered.get("execute.before")!
    // A bash command with no file paths must pass through the gate without
    // hitting the check engine, proving the payload reached the shared
    // dispatch (a structural failure would throw or reject here).
    await expect(
      before({ tool: "bash", input: { command: "echo hi" } }),
    ).resolves.toBeUndefined()
  })

  it("checks OpenCode 2.x tool shapes: read uses `path`, bash is `shell`", async () => {
    const hooks = await agentfilter.server({})
    const before = hooks["tool.execute.before"] as (
      input: { tool: string },
      output: { args: Record<string, unknown> },
    ) => Promise<void>

    // 2.x renamed the read tool's argument to `path` and the bash tool to
    // `shell`. Both must reach the shared gate. A sensitive path denies with
    // the CLI present (pattern match) and without it (fail-closed), so the
    // rejection is deterministic in every environment.
    await expect(
      before({ tool: "read" }, { args: { path: "~/.ssh/id_ed25519" } }),
    ).rejects.toThrow(/SECURITY BLOCK/)
    await expect(
      before({ tool: "shell" }, { args: { command: "cat ~/.ssh/id_ed25519" } }),
    ).rejects.toThrow(/SECURITY BLOCK/)
  })
})

