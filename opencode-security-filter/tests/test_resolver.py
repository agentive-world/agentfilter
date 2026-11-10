"""Tests for specificity resolver."""

from pathlib import Path
import pytest

from opencode_security.resolver import (
    find_matching_patterns,
    group_by_level,
    resolve,
)
from opencode_security.types import Operation, SpecificityLevel
from .fixtures.pattern_fixture import PatternFixture

_FIXTURE = PatternFixture(str(Path(__file__).parent / "fixtures" / "patterns.yaml"))


class TestFindMatchingPatterns:
    def test_finds_ssh_patterns(self):
        home = str(Path.home())
        matches = find_matching_patterns(f"{home}/.ssh/id_rsa")
        assert len(matches) > 0
        patterns = [m.pattern.pattern for m in matches]
        assert "~/.ssh/*" in patterns or any(".ssh" in p for p in patterns)

    def test_finds_pub_key_patterns(self):
        home = str(Path.home())
        matches = find_matching_patterns(f"{home}/.ssh/id_ed25519.pub")
        patterns = [m.pattern.pattern for m in matches]
        assert r"\.pub$" in patterns


class TestGroupByLevel:
    def test_groups_correctly(self):
        home = str(Path.home())
        matches = find_matching_patterns(f"{home}/.ssh/id_ed25519.pub")
        grouped = group_by_level(matches)
        # Should have FILE_EXTENSION level for *.pub
        assert SpecificityLevel.FILE_EXTENSION in grouped or SpecificityLevel.DIR_GLOB in grouped


class TestResolve:
    def test_pub_file_in_ssh_allowed(self):
        """*.pub (L2, ALLOW) supersedes ~/.ssh/* (L7, DENY)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(f"{home}/.ssh/id_ed25519.pub", False)
        assert decision == "allow"
        assert level == SpecificityLevel.FILE_EXTENSION
        assert pattern is not None
        assert pattern.pattern == r"\.pub$"

    def test_env_in_dotfiles_denied(self):
        """*.env (L2, DENY) supersedes ~/dotfiles/* (L7, ALLOW)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(f"{home}/dotfiles/.env", False)
        assert decision == "deny"
        assert level == SpecificityLevel.FILE_EXTENSION
        assert pattern.pattern == r"\.env$"

    def test_ssh_config_denied(self):
        """~/.ssh/config matches only ~/.ssh/* (L7, DENY)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(f"{home}/.ssh/config", False)
        assert decision == "deny"
        assert level == SpecificityLevel.DIR_GLOB

    def test_dotfiles_nix_allowed(self):
        """~/dotfiles/flake.nix matches only ~/dotfiles/* (L7, ALLOW)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(f"{home}/dotfiles/flake.nix", False)
        assert decision == "allow"
        assert level == SpecificityLevel.DIR_GLOB

    def test_secrets_dir_denied(self):
        """**/secrets/** (L4, DENY - SECURITY_DIRECTORY)"""
        decision, reason, pattern, level = resolve("/home/user/project/secrets/api.key", False)
        assert decision == "deny"
        assert level == SpecificityLevel.SECURITY_DIRECTORY

    def test_dotfiles_secrets_denied(self):
        """~/dotfiles/secrets should be DENIED by **/secrets/** (L4) not ALLOWED by ~/dotfiles/* (L6)"""
        home = str(Path.home())
        # This is the critical test: secrets dir inside trusted dotfiles should be denied
        decision, reason, pattern, level = resolve(f"{home}/dotfiles/secrets", False)
        assert decision == "deny"
        assert level == SpecificityLevel.SECURITY_DIRECTORY
        assert pattern.pattern == "(^|/)secrets(/|$)"

    def test_restrictive_perms_denied(self):
        """Mode 600 file with no pattern matches -> DENY at L6"""
        decision, reason, pattern, level = resolve("/tmp/random.txt", True)
        assert decision == "deny"
        assert level == SpecificityLevel.PERMISSIONS
        assert "restrictive permissions" in reason

    def test_no_match_passes(self):
        """File with no matches and permissive perms -> PASS"""
        decision, reason, pattern, level = resolve("/etc/hostname", False)
        assert decision == "pass"
        assert pattern is None
        assert level is None


class TestTrustedDirResolution:
    def test_claude_projects_read_allowed(self):
        """~/.claude/projects/foo/memory READ -> ALLOW at TRUSTED_DIR"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(
            f"{home}/.claude/projects/foo/memory/bar.md", False, Operation.READ
        )
        assert decision == "allow"
        assert level == SpecificityLevel.TRUSTED_DIR

    def test_claude_projects_write_passes(self):
        """~/.claude/projects/foo WRITE -> PASS (allowed_ops=READ only)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(
            f"{home}/.claude/projects/foo/memory/bar.md", False, Operation.WRITE
        )
        assert decision == "pass"

    def test_claude_projects_unknown_passes(self):
        """~/.claude/projects/foo UNKNOWN -> PASS"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(
            f"{home}/.claude/projects/foo/memory/bar.md", False, Operation.UNKNOWN
        )
        assert decision == "pass"

    def test_claude_projects_secrets_still_denied(self):
        """secrets inside ~/.claude/projects -> DENY at SECURITY_DIRECTORY (L4 beats L5)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(
            f"{home}/.claude/projects/foo/secrets/api.key", False, Operation.READ
        )
        assert decision == "deny"
        assert level == SpecificityLevel.SECURITY_DIRECTORY

    def test_claude_projects_credential_denied(self):
        """credential in ~/.claude/projects -> DENY (SECURITY_DIRECTORY)"""
        home = str(Path.home())
        decision, reason, pattern, level = resolve(
            f"{home}/.claude/projects/foo/credential.json", False, Operation.READ
        )
        assert decision == "deny"
        assert level == SpecificityLevel.SECURITY_DIRECTORY


class TestSourceCodeExclusion:
    """Source code files with credential/password in the name should not be blocked.

    Extensions and test paths loaded from tests/fixtures/patterns.yaml.
    """

    @pytest.mark.parametrize("ext", _FIXTURE.source_code_extensions)
    def test_credentials_source_file_not_blocked(self, ext):
        """credentials.{ext} should PASS (not blocked by credential pattern)"""
        decision, reason, pattern, level = resolve(
            f"/home/user/dev/auth/credentials.{ext}", False
        )
        assert decision == "pass", f"credentials.{ext} should pass, got {decision}: {reason}"

    @pytest.mark.parametrize("ext", _FIXTURE.source_code_extensions)
    def test_password_source_file_not_blocked(self, ext):
        """password_utils.{ext} should PASS"""
        decision, reason, pattern, level = resolve(
            f"/home/user/dev/auth/password_utils.{ext}", False
        )
        assert decision == "pass", f"password_utils.{ext} should pass, got {decision}: {reason}"

    @pytest.mark.parametrize("ext", _FIXTURE.source_code_extensions)
    def test_credential_handler_deep_path_not_blocked(self, ext):
        """credential_handler.{ext} in a deep path should PASS"""
        decision, reason, pattern, level = resolve(
            f"/home/user/dev/agent-data-leverage/jon-auth/internal/auth/credential_handler.{ext}",
            False,
        )
        assert decision == "pass", f"credential_handler.{ext} should pass, got {decision}: {reason}"

    @pytest.mark.parametrize(
        "path",
        _FIXTURE.source_code_exclusion_paths
        .get("credential_data_files_still_blocked", {})
        .get("paths", []),
    )
    def test_credential_data_files_still_blocked(self, path):
        """Data files with 'credential' in name should still be DENIED"""
        decision, reason, pattern, level = resolve(path, False)
        assert decision == "deny", f"{path} should be denied, got {decision}: {reason}"
        assert level == SpecificityLevel.SECURITY_DIRECTORY

    @pytest.mark.parametrize(
        "path",
        _FIXTURE.source_code_exclusion_paths
        .get("password_data_files_still_blocked", {})
        .get("paths", []),
    )
    def test_password_data_files_still_blocked(self, path):
        """Data files with 'password' in name should still be DENIED"""
        decision, reason, pattern, level = resolve(path, False)
        assert decision == "deny", f"{path} should be denied, got {decision}: {reason}"
        assert level == SpecificityLevel.SECURITY_DIRECTORY

    def test_secrets_dir_still_blocks_source_files(self):
        """Source file INSIDE secrets/ dir should still be blocked by secrets pattern"""
        decision, reason, pattern, level = resolve(
            "/home/user/project/secrets/credentials.go", False
        )
        assert decision == "deny"
        assert level == SpecificityLevel.SECURITY_DIRECTORY
        assert "secrets" in pattern.pattern
