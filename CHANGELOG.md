# Changelog

## [0.5.0] - 2026-11-10

### Added
- **Content shield**: regex-mode PII redaction (15 patterns: credit card, SSN, email, phone US/CN, IPv4, DOB, API keys, AWS keys, GitHub tokens, passwords, JWT, private key headers) scrubbed from message text before the model sees them (`session.hook("context")`, OpenCode 2.x). Pure TypeScript port of privacy-filter.py's regex mode — zero dependencies, no engine call
- `AGENTFILTER_DISABLE_CONTENT_SHIELD=1` opt-out
- 18 content-shield tests

### Changed
- The OpenCode plugin now installs **both shields in one file**: path shield (`tool.execute.before`, all OpenCode generations) + content shield (2.x). The separate privacy-filter plugin is retired
- Repo moved to the `agentive-world` organization

### Fixed
- Path checks silently passed on OpenCode 2.x: the read/write tools' primary argument is `path` (not 1.x's `file_path`/`filePath`) and the bash tool is named `shell`. All generations' tool shapes are now mapped and verified against a live 2.1.2 session

## [0.4.0] - 2026-11-10

### Added
- OpenCode plugin dual entry points for every loader generation: named export (1.x ≤ 1.3.3), `default.server` (1.3.4+), `default.setup` registering `ctx.tool.hook("execute.before")` (2.x)
- Single-file bundle build (`bun run build`); `install-to-opencode` now builds and copies the bundle as `agentfilter.js`
- Entry-point shape tests (`src/__tests__/exports.test.ts`)
- CONTRIBUTING.md and SECURITY.md

### Changed
- Plugin identity renamed to `agentfilter` to avoid clashing with directory-style installs of the old plugin
- README refreshed: agentfilter branding, why/demo sections, updated OpenCode install

### Fixed
- `checkPath` failed open when the engine CLI was unreachable; it now fails closed by default (`SECURITY_FILTER_ALLOW_UNCHECKED=1` restores availability-first behavior)

## [0.3.0] - 2026-02-23

### Added
- feat: add TRUSTED_DIR level and Operation-aware filtering
- feat(hook): rewrite as protocol translator delegating to SecurityProxy
- feat: extend path extraction and pass operation to filter
- feat: add Claude Code plugin with PreToolUse security filter hook
- feat: adds symlinked CLAUDE and GEMINI
- feat: track git hooks in .githooks/ and activate via devShell
- feat: add requirements.txt and requirements.dev.txt with pre-commit hook
- feat: migrate flake.nix from buildPythonPackage to uv2nix
- feat: add flake.nix with buildPythonPackage and devShell
- feat: adds package-lock.json
- feat: initial extraction from dotfiles monorepo

### Fixed
- fix: exclude source code files from credential/password substring matching
- fix: move hook script next to package so import resolves naturally
- fix: add sys.path setup so hook finds opencode_security without pip install
- fix: remove unrecognized 'marketplace' key from plugin manifest

### Changed
- refactor(test): extract inline test values into fixtures
- refactor: import SecurityFilter directly instead of shelling out to CLI

### Documentation
- docs: rewrite README with install, usage, design, and test instructions

### Other
- beads pain
- chore: bump version to 0.2.0
- test: add TRUSTED_DIR, Operation, and hook tests (Slice E)
- chore: rename plugin to agentfilter with marketplace reference
- chore: close uv2nix migration beads
- chore: initialize beads and track uv2nix migration epic
