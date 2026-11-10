"""Tests for security_filter_hook.py (Claude Code PreToolUse hook)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest


HOOK_PATH = str(Path(__file__).parent.parent / "src" / "security_filter_hook.py")


def run_hook(tool_name: str, tool_input: dict) -> tuple[int, str, str]:
    """Run the hook script with given input, return (exit_code, stdout, stderr)."""
    input_data = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    result = subprocess.run(
        [sys.executable, HOOK_PATH],
        input=input_data,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestHookDenied:
    def test_ssh_key_blocked(self):
        home = str(Path.home())
        code, stdout, stderr = run_hook("Read", {"file_path": f"{home}/.ssh/id_rsa"})
        assert code == 2
        assert "DANGEROUS" in stderr or "SECURITY BLOCK" in stderr

    def test_env_file_blocked(self):
        code, stdout, stderr = run_hook("Read", {"file_path": "/home/user/.env"})
        assert code == 2


class TestHookAllowed:
    def test_safe_path_passes(self):
        code, stdout, stderr = run_hook("Read", {"file_path": "/tmp/safe.txt"})
        assert code == 0

    def test_claude_projects_read_allowed(self):
        home = str(Path.home())
        code, stdout, stderr = run_hook("Read", {"file_path": f"{home}/.claude/projects/foo/memory/bar"})
        assert code == 0


class TestHookEdgeCases:
    def test_no_tool_name_passes(self):
        code, stdout, stderr = run_hook("", {})
        assert code == 0

    def test_unknown_tool_passes(self):
        code, stdout, stderr = run_hook("SomeTool", {"random": "field"})
        assert code == 0
