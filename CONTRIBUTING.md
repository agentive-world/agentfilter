# Contributing to agentfilter

Thanks for helping make agentfilter better. This project filters AI agent
tool calls before they execute, so changes here have real security
consequences — please read the PR checklist at the bottom.

## Dev setup

Fork and clone the repo, then set up either way:

### With Nix (recommended)

```bash
nix develop
```

This provides Python 3.12 with an editable install of the engine, `uv`,
`ruff`, `bun`, and activates the versioned git hooks.

### Without Nix

```bash
cd opencode-security-filter
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

cd ../opencode-plugin
bun install
```

## Running tests

Python engine (pytest):

```bash
cd opencode-security-filter
uv run pytest -v
```

Test suites cover the filter itself, pattern matching (including
combinatorial coverage), the specificity resolver, path canonicalization
and symlinks, the JSON-RPC proxy, ACP compliance, integration, and
benchmarks.

OpenCode plugin (vitest):

```bash
cd opencode-plugin
bun run test
```

Covers bash AST edge cases and the plugin entry-point shapes (named export
/ `default.server` / `default.setup`).

## Commit style

Short, prefixed subjects, matching the existing history:

- `feat:` new capability
- `fix:` bug fix
- `doc:` docs only
- `chore:` tooling and housekeeping

## PR checklist

- [ ] Both test suites pass (`uv run pytest`, `bun run test`)
- [ ] New deny/allow patterns include test cases and a one-line rationale
      (why is this path sensitive?)
- [ ] Blocking behavior stays **fail-closed**: engine errors deny, never
      silently allow
- [ ] Symlink handling considered if your change touches path resolution
- [ ] `CHANGELOG.md` updated under a version heading
- [ ] No real secrets, keys, or personal paths in new fixtures

## Security-relevant changes

Anything that changes when a path is allowed or denied deserves explicit
tests on both sides: a path that must be denied, and a similar path that
must pass. If your change could weaken blocking, call it out in the PR
description so reviewers look at it specifically.

## Reporting vulnerabilities

Do not open a public issue for exploitable behavior (e.g., a bypass). See
[SECURITY.md](SECURITY.md) for private reporting.
