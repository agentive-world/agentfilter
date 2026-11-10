# Changelog

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
