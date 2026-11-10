---
title: "OpenCode Plugin Installation — Domain Research"
date: "2026-02-26"
depth: "standard-research"
request: "standalone"
---

## Executive Summary

OpenCode loads TypeScript/JavaScript plugins from `~/.config/opencode/plugins/` (global)
or `.opencode/plugins/` (project-level). Dependencies for local plugins are declared in
`~/.config/opencode/package.json`; OpenCode auto-runs `bun install` at startup.

**Current state:** All prerequisites for this plugin are already satisfied on this machine.
The only missing step is copying `security-filter.ts` into the plugins directory. The
existing `install-to-opencode` npm script does exactly that.

---

## Plugin Loading

### How OpenCode Finds Plugins

OpenCode loads plugins in this order at startup:

1. npm plugins listed in `opencode.json` under `"plugin"` (e.g. `opencode-antigravity-auth@latest`)
2. Files in `~/.config/opencode/plugins/` (global)
3. Files in `.opencode/plugins/` (project-level)

For local `.ts` files OpenCode runs them directly via Bun (which handles TypeScript
natively). No compilation step is required.

### Plugin Entry Point

A plugin file must export a `Plugin`-typed function:

```ts
// opencode-plugin/src/security-filter.ts:16
export const SecurityFilterPlugin: Plugin = async ({ client }) => { ... }
```

OpenCode discovers the export by name convention — any named export whose value
satisfies the `Plugin` type is registered.

### Assessment

| Aspect | npm plugin | Local .ts file |
|--------|-----------|----------------|
| Install | Listed in opencode.json | Copy to plugins dir |
| Deps | Bundled in package | Declared in config package.json |
| Updates | `@latest` auto-updates | Manual copy on change |
| Scope | Global | Global or per-project |

**Adoption recommendation:** Local `.ts` file approach is what the project already uses — correct for this use case.

---

## Dependency Management

### How Dependencies Work

Local plugins share a single `package.json` in the config root.
OpenCode runs `bun install` at startup to materialize them into
`~/.config/opencode/node_modules/`.

The config's `package.json` (`~/.config/opencode/package.json`) already contains:

```json
{
  "dependencies": {
    "@opencode-ai/plugin": "1.2.10",
    "@types/node": "^22.0.0",
    "bash-parser": "^0.5.0"
  }
}
```

`node_modules/` and `bun.lock` are already present, meaning `bun install` has already run.

### Python Backend

The plugin shells out to `opencode-security-filter`:

```ts
// opencode-plugin/src/security-filter.ts:233-237
const result = execSync(
  `opencode-security-filter --check "${path.replace(/"/g, '\\"')}"`,
  { encoding: "utf-8", timeout: 5000 }
)
```

`opencode-security-filter` is already installed at `~/.local/bin/opencode-security-filter`
and is on PATH.

### Assessment

| Dependency | Status |
|-----------|--------|
| `@opencode-ai/plugin` | Installed in `~/.config/opencode/node_modules/` |
| `bash-parser` | Installed in `~/.config/opencode/node_modules/` |
| `@types/node` | Installed in `~/.config/opencode/node_modules/` |
| `opencode-security-filter` | On PATH at `~/.local/bin/` |

**All satisfied. No action needed.**

---

## Installation Steps

Everything is pre-satisfied except the file copy itself.

### Step 1 — Copy the plugin file

```bash
cd ~/codebases/dayvidpham/agentfilter/opencode-plugin
bun run install-to-opencode
# equivalent: cp src/security-filter.ts ~/.config/opencode/plugins/
```

This copies `security-filter.ts` into `~/.config/opencode/plugins/`.

### Step 2 — Restart OpenCode

OpenCode loads plugins at startup. Restart it (or open a new session) for the
plugin to take effect. `bun install` will run automatically if `package.json`
changed; in this case it won't since deps are already installed.

### That's it

No config file changes needed. No `opencode.json` edits. The plugin auto-registers
by being present in the plugins directory.

---

## Summary

| Topic Area | Recommendation | Rationale |
|------------|---------------|-----------|
| Plugin loading | Adopt local .ts pattern | Already implemented, correct approach |
| Dependency setup | Already done | `package.json` + `node_modules` exist |
| Python backend | Already done | `opencode-security-filter` on PATH |
| Installation | Run `bun run install-to-opencode` | Single command copies the file |

## Key Takeaways

### Adopt
- OpenCode loads any `.ts` file in `~/.config/opencode/plugins/` automatically at startup
- Dependencies go in `~/.config/opencode/package.json`; bun install runs at startup

### Skip
- No need to modify `opencode.json` — that's only for npm-distributed plugins
- No compilation step — Bun handles TypeScript natively
