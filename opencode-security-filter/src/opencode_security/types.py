"""OpenCode Security Filter - Type definitions."""

import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Literal


class SpecificityLevel(IntEnum):
    """Precedence levels (lower = more specific, wins).

    Resolution order: levels 1-5 checked first, then PERMISSIONS (6),
    then levels 7-8. DENY supersedes ALLOW at each level.

    Note: Level integer values appear in the JSON-RPC error response
    'level' field (informational only, not used for routing).
    """

    FILE_NAME = 1  # Exact file path: ~/.ssh/id_ed25519
    FILE_EXTENSION = 2  # Extension glob: *.pub, *.env
    DIRECTORY = 3  # Exact directory: ~/.ssh/
    SECURITY_DIRECTORY = 4  # Security-critical dir names: **/secrets/**, *credentials*
    TRUSTED_DIR = 5  # Agent data dirs: overrides perms, respects security dirs
    PERMISSIONS = 6  # Mode bits: 600, 400
    DIR_GLOB = 7  # Dir + glob: ~/.ssh/*, ~/dotfiles/*
    GLOB_MIDDLE = 8  # Glob in middle: other patterns


class Operation(Enum):
    """Tool operation type for read/write-aware filtering."""

    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"


# Tool name to operation mapping
_READ_TOOLS: frozenset[str] = frozenset({
    "Read", "read_file", "Glob", "Grep",
})
_WRITE_TOOLS: frozenset[str] = frozenset({
    "Write", "write_file", "Edit", "edit_file",
    "MultiEdit", "NotebookEdit",
})


def classify_operation(tool_name: str) -> Operation:
    """Classify a tool name as a read, write, or unknown operation.

    Args:
        tool_name: The tool name from the agent's tool call.

    Returns:
        Operation.READ for read-only tools, Operation.WRITE for
        mutating tools, Operation.UNKNOWN for bash and unrecognized tools.
    """
    if tool_name in _READ_TOOLS:
        return Operation.READ
    if tool_name in _WRITE_TOOLS:
        return Operation.WRITE
    return Operation.UNKNOWN


Decision = Literal["allow", "deny", "pass"]
PermissionOutcome = Literal[
    "allow_once", "allow_always", "reject_once", "reject_always", "cancelled"
]


@dataclass
class SecurityPattern:
    """A security pattern with its decision and specificity level.

    The pattern field contains a regex string that will be compiled on first use.
    Use the matches() method to check if a path matches the pattern.

    The optional allowed_ops field restricts when an allow pattern fires:
    - None (default): pattern is operation-agnostic (matches any operation).
      This is the correct default for deny patterns and legacy allow patterns.
    - frozenset of Operations: pattern only matches if the current operation
      is in the set. Use for read/write-aware allow patterns.
    """

    pattern: str
    decision: Literal["allow", "deny"]
    level: SpecificityLevel
    description: str
    allowed_ops: frozenset[Operation] | None = None
    _regex: re.Pattern | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile the regex pattern on initialization."""
        object.__setattr__(self, "_regex", re.compile(self.pattern))

    def matches(self, path: str, operation: Operation = Operation.UNKNOWN) -> bool:
        """Check if the given path matches this pattern.

        Args:
            path: The file path to check against the pattern.
            operation: The operation type. If this pattern has allowed_ops set
                and the operation is not in the set, returns False.

        Returns:
            True if the pattern matches the path (and operation), False otherwise.
        """
        if self._regex is None:
            object.__setattr__(self, "_regex", re.compile(self.pattern))
        if not self._regex.search(path):
            return False
        # If allowed_ops is set and this is an allow pattern, check operation
        if self.allowed_ops is not None and self.decision == "allow":
            return operation in self.allowed_ops
        return True

    def __hash__(self) -> int:
        """Make SecurityPattern hashable for use in sets and as dict keys."""
        return hash((self.pattern, self.decision, self.level, self.description))

    def __eq__(self, other: object) -> bool:
        """Check equality based on pattern fields (not the compiled regex)."""
        if not isinstance(other, SecurityPattern):
            return NotImplemented
        return (
            self.pattern == other.pattern
            and self.decision == other.decision
            and self.level == other.level
            and self.description == other.description
        )


@dataclass(frozen=True)
class PatternMatch:
    """A matched pattern with the path it matched."""

    pattern: SecurityPattern
    matched_path: str


@dataclass
class CheckResult:
    """Result of a security check."""

    decision: Decision
    reason: str
    file_path: str
    canonical_path: str
    matched_pattern: SecurityPattern | None = None
    matched_level: SpecificityLevel | None = None


@dataclass
class PermissionRequest:
    """ACP permission request from agent."""

    id: str | int
    session_id: str
    tool_call_id: str
    tool_name: str
    tool_input: dict
    options: list[PermissionOutcome]


@dataclass
class PermissionResponse:
    """ACP permission response to agent."""

    id: str | int
    outcome: PermissionOutcome
    reason: str | None = None


# Exceptions
class SecurityFilterError(Exception):
    """Base exception for security filter errors."""

    pass


class PathResolutionError(SecurityFilterError):
    """Error resolving/canonicalizing path."""

    pass


class CircularSymlinkError(PathResolutionError):
    """Circular symlink detected."""

    pass


__all__ = [
    "SpecificityLevel",
    "Operation",
    "classify_operation",
    "Decision",
    "PermissionOutcome",
    "SecurityPattern",
    "PatternMatch",
    "CheckResult",
    "PermissionRequest",
    "PermissionResponse",
    "SecurityFilterError",
    "PathResolutionError",
    "CircularSymlinkError",
]
