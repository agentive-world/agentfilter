# opencode-security

Security filter that prevents AI coding agents from accessing sensitive files.
Ships as a **Claude Code plugin** and an **OpenCode plugin**, backed by a shared
Python filter engine.

## What it does

Intercepts tool calls (file reads, writes, edits, bash commands) **before they
execute** and blocks access to sensitive paths: SSH keys, cloud credentials,
environment files, GPG keyrings, and anything with restrictive file permissions.

Decisions use **specificity-based precedence** so more-specific rules always win
and allowlists can coexist with denylists at different levels.

## Install

### Prerequisites

- Python 3.11+ (for the filter engine)
- [uv](https://docs.astral.sh/uv/) (for dependency management)
- [Nix](https://nixos.org/) (optional, for the devShell)

### As a Claude Code plugin

```bash
# From the repo root:
claude plugin install .
```

This registers the `PreToolUse` hook that checks every `Read`, `Write`, `Edit`,
`Glob`, `Grep`, and `Bash` call against the filter.

The plugin requires the Python package to be importable. Install it:

```bash
cd opencode-security-filter
uv pip install -e .
```

Or with Nix:

```bash
nix develop   # enters devShell with editable install + all tooling
```

### As an OpenCode plugin

Copy the TypeScript plugin to your OpenCode plugins directory:

```bash
cd opencode-plugin
bun install
bun run install-to-opencode
```

The OpenCode plugin also requires `opencode-security-filter` on `PATH`.

## Usage

### CLI (standalone)

```bash
# Check a single path
opencode-security-filter --check ~/.ssh/id_ed25519
# => Decision: deny
# => Reason: Blocked by (^|/)id_ed25519$ (Ed25519 private key)

opencode-security-filter --check ~/codebases/myproject/README.md
# => Decision: pass
# => Reason: No matching patterns

# Run as JSON-RPC proxy (stdin/stdout)
opencode-security-filter
```

### In Claude Code

Once installed as a plugin, it works automatically. Every tool call is checked
before execution. Blocked calls return exit code 2 with a reason on stderr,
which Claude Code surfaces as feedback.

## Design principles

1. **Fail-closed**: errors during checking result in DENY, not silent passthrough
2. **Specificity wins**: a FILE_NAME rule for `id_ed25519` overrides a DIR_GLOB
   allow on `~/.ssh/*` -- the most-specific match always takes precedence
3. **DENY supersedes ALLOW at equal specificity**: if both exist at the same
   level, deny wins
4. **Permission-aware**: files with restrictive mode bits (no others-read, e.g.
   `chmod 600`) are blocked even without an explicit pattern
5. **Symlink-safe**: paths are canonicalized (resolving `~`, `..`, symlinks)
   before matching, with a depth limit to prevent circular symlink attacks

## Specificity levels

Checked in order, highest priority first:

| Level | Name | Example | Priority |
|-------|------|---------|----------|
| 1 | FILE_NAME | `~/.netrc`, `id_ed25519` | Highest |
| 2 | FILE_EXTENSION | `*.env`, `*.pub` | |
| 3 | DIRECTORY | exact directory match | |
| 4 | SECURITY_DIRECTORY | `**/secrets/**`, `*credential*` | |
| 5 | PERMISSIONS | file mode bits (600, 400) | |
| 6 | DIR_GLOB | `~/.ssh/*`, `~/dotfiles/*` | |
| 7 | GLOB_MIDDLE | other glob patterns | Lowest |

## Blocked patterns

**Denied by default:**

- SSH private keys: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `id_ecdsa_sk`, `id_ed25519_sk`
- SSH directory contents: `~/.ssh/*`
- GPG keyring: `~/.gnupg/*`
- Cloud credentials: `~/.aws/*`, `~/.config/gcloud/*`, `~/.azure/*`, `~/.config/sops/*`
- Environment files: `*.env`, `*.env.*`
- Credential/password files: any path containing `credential` or `password`
- Secrets directories: `**/secrets/**`, `**/secret/**`, `**/.secrets/**`, `**/.secret/**`
- Auth files: `~/.netrc`
- Files with restrictive permissions (no others-read bit)

**Allowed by default:**

- Public keys: `*.pub`
- PEM certificates: `*.pem`
- Trusted directories: `~/dotfiles/*`, `~/codebases/*`

## Running tests

### Python filter engine

```bash
cd opencode-security-filter

# Using pytest directly (inside nix develop or with venv active)
pytest

# Or via uv
uv run pytest

# Verbose
uv run pytest -v
```

Test suites:
- `test_filter.py` -- SecurityFilter unit tests
- `test_patterns.py` -- pattern matching
- `test_patterns_combinatorial.py` -- combinatorial pattern coverage
- `test_resolver.py` -- specificity resolution algorithm
- `test_paths.py` -- path canonicalization and symlink handling
- `test_proxy.py` -- JSON-RPC proxy protocol
- `test_acp.py` -- ACP compliance
- `test_integration.py` -- end-to-end integration tests
- `test_benchmark.py` -- performance benchmarks

### OpenCode TypeScript plugin

```bash
cd opencode-plugin
bun test
```

## Development

### With Nix (recommended)

```bash
nix develop
```

This gives you: Python 3.12 with editable install, uv, ruff, bun, and
auto-configures git hooks (requirements export on commit, beads sync).

### Without Nix

```bash
cd opencode-security-filter
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Project structure

```
.claude-plugin/          # Claude Code plugin manifest
hooks/
  hooks.json             # PreToolUse hook configuration
  security_filter_hook.py  # Hook script (JSON stdin adapter)
opencode-security-filter/  # Python filter engine
  src/opencode_security/
    filter.py            # SecurityFilter class
    resolver.py          # Specificity-based resolution
    patterns.py          # Pattern definitions (regex)
    paths.py             # Path canonicalization
    types.py             # Type definitions
    proxy.py             # JSON-RPC proxy mode
  tests/                 # pytest test suites
opencode-plugin/         # OpenCode TypeScript plugin
  src/security-filter.ts # Plugin with bash-parser AST extraction
.githooks/               # Version-controlled git hooks
flake.nix                # Nix devShell and package definitions
```

## License

MIT
