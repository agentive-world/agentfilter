"""Tests for pattern matching."""

import re
from pathlib import Path

import pytest

from opencode_security.patterns import (
    PATTERNS,
    _build_recursive_dir_regex,
    _build_substring_deny_regex,
    expand_pattern,
    match_pattern,
)
from opencode_security.types import SpecificityLevel
from .fixtures.pattern_fixture import PatternFixture

_FIXTURE = PatternFixture(str(Path(__file__).parent / "fixtures" / "patterns.yaml"))


class TestExpandPattern:
    def test_expands_tilde(self):
        result = expand_pattern("~/.ssh/id_rsa")
        assert result == str(Path.home() / ".ssh" / "id_rsa")

    def test_no_tilde_unchanged(self):
        result = expand_pattern("/etc/passwd")
        assert result == "/etc/passwd"


class TestMatchPattern:
    def test_extension_glob_pub(self):
        home = str(Path.home())
        assert match_pattern("*.pub", f"{home}/.ssh/id_ed25519.pub")
        assert not match_pattern("*.pub", f"{home}/.ssh/id_ed25519")

    def test_extension_glob_env(self):
        assert match_pattern("*.env", "/home/user/project/.env")
        assert match_pattern("*.env.*", "/home/user/.env.local")
        assert not match_pattern("*.env", "/home/user/env")

    def test_dir_glob_ssh(self):
        home = str(Path.home())
        assert match_pattern("~/.ssh/*", f"{home}/.ssh/config")
        assert match_pattern("~/.ssh/*", f"{home}/.ssh/id_rsa")

    def test_dir_glob_ssh_does_not_recurse(self):
        """Single * should not match subdirectories."""
        home = str(Path.home())
        # This should NOT match because * doesn't recurse
        assert not match_pattern("~/.ssh/*", f"{home}/.ssh/subdir/file")

    def test_glob_middle_secrets(self):
        assert match_pattern("**/secrets/**", "/any/path/secrets/api.key")
        assert match_pattern("**/secrets/**", "/home/user/project/secrets/db.json")
        # Should also match the directory itself, not just contents
        assert match_pattern("**/secrets/**", "/any/path/secrets")
        assert match_pattern("**/secrets/**", "/home/user/project/secrets")

    def test_glob_middle_credentials(self):
        assert match_pattern("*credentials*", "/path/to/credentials.json")
        assert match_pattern("*credentials*", "/path/aws_credentials")

    def test_exact_file_name(self):
        home = str(Path.home())
        assert match_pattern("~/.netrc", f"{home}/.netrc")
        assert not match_pattern("~/.netrc", f"{home}/.ssh/.netrc")


class TestPatternsConfig:
    def test_all_patterns_have_valid_levels(self):
        for p in PATTERNS:
            assert p.level in SpecificityLevel

    def test_has_ssh_patterns(self):
        ssh_patterns = [p for p in PATTERNS if ".ssh" in p.pattern]
        assert len(ssh_patterns) > 0

    def test_has_trusted_patterns(self):
        trusted = [p for p in PATTERNS if p.decision == "allow"]
        assert len(trusted) > 0

    def test_has_deny_patterns(self):
        deny = [p for p in PATTERNS if p.decision == "deny"]
        assert len(deny) > 0

    def test_has_all_specificity_levels(self):
        """Verify we have patterns at multiple specificity levels."""
        levels_present = {p.level for p in PATTERNS}
        assert SpecificityLevel.FILE_NAME in levels_present
        assert SpecificityLevel.FILE_EXTENSION in levels_present
        assert SpecificityLevel.DIR_GLOB in levels_present
        assert SpecificityLevel.SECURITY_DIRECTORY in levels_present
        assert SpecificityLevel.TRUSTED_DIR in levels_present


class TestRecursiveDirPattern:
    def test_trusted_dir_pattern_exists(self):
        trusted = [p for p in PATTERNS if p.level == SpecificityLevel.TRUSTED_DIR]
        assert len(trusted) >= 1
        assert any("claude" in p.pattern for p in trusted)

    def test_recursive_matches_descendants(self):
        regex = re.compile(_build_recursive_dir_regex("~/.claude/projects"))
        home = str(Path.home())
        assert regex.search(f"{home}/.claude/projects/foo/bar")
        assert regex.search(f"{home}/.claude/projects")
        assert not regex.search(f"{home}/.claude/settings")


class TestSubstringDenyPattern:
    """Tests for _build_substring_deny_regex — substring match excluding source code files.

    Extensions loaded from tests/fixtures/patterns.yaml.
    """

    @pytest.mark.parametrize("ext", _FIXTURE.data_file_extensions[:3])
    def test_matches_data_file_with_substring(self, ext):
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert regex.search(f"/path/to/credentials.{ext}")

    @pytest.mark.parametrize("ext", _FIXTURE.source_code_extensions)
    def test_excludes_source_code_files(self, ext):
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert not regex.search(f"/path/to/credentials.{ext}"), (
            f"credentials.{ext} should NOT be matched by credential deny pattern"
        )

    def test_matches_directory_with_substring(self):
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert regex.search("/path/credentials/config")
        assert regex.search("/path/credential-store/data")

    def test_matches_no_extension(self):
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert regex.search("/path/aws_credentials")

    def test_does_not_match_without_substring(self):
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert not regex.search("/path/to/config.json")
        assert not regex.search("/path/to/handler.go")

    @pytest.mark.parametrize("ext", _FIXTURE.source_code_extensions)
    def test_password_pattern_excludes_source(self, ext):
        regex = re.compile(_build_substring_deny_regex("password"))
        assert not regex.search(f"/path/to/password_utils.{ext}"), (
            f"password_utils.{ext} should NOT be matched by password deny pattern"
        )

    @pytest.mark.parametrize("ext", _FIXTURE.data_file_extensions[:3])
    def test_password_pattern_blocks_data_files(self, ext):
        regex = re.compile(_build_substring_deny_regex("password"))
        assert regex.search(f"/path/to/passwords.{ext}")

    def test_deep_path_with_credential_source_file(self):
        """Exact reproduction of the reported bug."""
        regex = re.compile(_build_substring_deny_regex("credential"))
        assert not regex.search(
            "/home/user/dev/agent-data-leverage/jon-auth/internal/auth/credentials.go"
        )
