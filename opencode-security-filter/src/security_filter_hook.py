#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for opencode-security-filter.

Thin protocol translator: reads Claude Code hook JSON from stdin,
constructs an ACP JSON-RPC permission request, and delegates to
SecurityProxy for all security decisions.
"""

import json
import sys

from opencode_security.acp import format_security_block_stderr
from opencode_security.proxy import SecurityProxy


def main() -> None:
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    acp_msg = {
        "jsonrpc": "2.0",
        "id": "hook-1",
        "method": "session/request_permission",
        "params": {
            "sessionId": "hook",
            "toolCall": {
                "toolCallId": "hook-tc",
                "name": tool_name,
                "input": tool_input,
            },
            "options": ["allow_once", "reject_once"],
        },
    }

    proxy = SecurityProxy()
    response_bytes, should_forward = proxy.process_agent_message(
        json.dumps(acp_msg).encode()
    )

    if response_bytes is None and should_forward:
        # Pass: let Claude Code prompt the user
        sys.exit(0)

    if response_bytes is not None:
        response = json.loads(response_bytes)

        if "error" in response:
            print(
                format_security_block_stderr(response["error"]["data"]),
                file=sys.stderr,
            )
            sys.exit(2)

        # result with allow_once -> permitted
        sys.exit(0)

    # Fallback: allow
    sys.exit(0)


if __name__ == "__main__":
    main()
