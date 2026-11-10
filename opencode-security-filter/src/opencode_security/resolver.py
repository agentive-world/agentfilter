"""Specificity-based resolution algorithm."""

from .types import (
    SecurityPattern, PatternMatch, SpecificityLevel, Decision, Operation
)
from .patterns import PATTERNS


def find_matching_patterns(
    canonical_path: str,
    operation: Operation = Operation.UNKNOWN,
) -> list[PatternMatch]:
    """Find all patterns that match the given path and operation."""
    matches = []
    for pattern in PATTERNS:
        if pattern.matches(canonical_path, operation):
            matches.append(PatternMatch(pattern=pattern, matched_path=canonical_path))
    return matches


def group_by_level(matches: list[PatternMatch]) -> dict[SpecificityLevel, list[PatternMatch]]:
    """Group pattern matches by their specificity level."""
    grouped: dict[SpecificityLevel, list[PatternMatch]] = {}
    for match in matches:
        level = match.pattern.level
        if level not in grouped:
            grouped[level] = []
        grouped[level].append(match)
    return grouped


def resolve(
    canonical_path: str,
    has_restrictive_perms: bool,
    operation: Operation = Operation.UNKNOWN,
) -> tuple[Decision, str, SecurityPattern | None, SpecificityLevel | None]:
    """Resolve decision using specificity-based precedence.

    Algorithm:
    1. Find all matching patterns (considering operation for allowed_ops)
    2. Group by specificity level
    3. Check levels in order:
       FILE_NAME(1) > FILE_EXTENSION(2) > DIRECTORY(3) >
       SECURITY_DIRECTORY(4) > TRUSTED_DIR(5) > PERMISSIONS(6) >
       DIR_GLOB(7) > GLOB_MIDDLE(8)
    4. At each level: DENY supersedes ALLOW
    5. Level 6 (PERMISSIONS): check file mode bits
    6. If no matches: pass through

    Returns:
        (decision, reason, matched_pattern, matched_level)
    """
    matches = find_matching_patterns(canonical_path, operation)
    grouped = group_by_level(matches)

    # Check levels 1-5 (file name, extension, directory, security directory, trusted dir)
    for level in [
        SpecificityLevel.FILE_NAME,
        SpecificityLevel.FILE_EXTENSION,
        SpecificityLevel.DIRECTORY,
        SpecificityLevel.SECURITY_DIRECTORY,
        SpecificityLevel.TRUSTED_DIR,
    ]:
        if level in grouped:
            patterns_at_level = grouped[level]
            # DENY supersedes ALLOW at same level
            for match in patterns_at_level:
                if match.pattern.decision == "deny":
                    return ("deny", f"Blocked by {match.pattern.pattern} ({match.pattern.description})", match.pattern, level)
            for match in patterns_at_level:
                if match.pattern.decision == "allow":
                    return ("allow", f"Allowed by {match.pattern.pattern} ({match.pattern.description})", match.pattern, level)

    # Level 6: Permission mode bits
    if has_restrictive_perms:
        return ("deny", "File has restrictive permissions (no others read)", None, SpecificityLevel.PERMISSIONS)

    # Check levels 7-8 (dir-glob, glob-middle)
    for level in [SpecificityLevel.DIR_GLOB, SpecificityLevel.GLOB_MIDDLE]:
        if level in grouped:
            patterns_at_level = grouped[level]
            for match in patterns_at_level:
                if match.pattern.decision == "deny":
                    return ("deny", f"Blocked by {match.pattern.pattern} ({match.pattern.description})", match.pattern, level)
            for match in patterns_at_level:
                if match.pattern.decision == "allow":
                    return ("allow", f"Allowed by {match.pattern.pattern} ({match.pattern.description})", match.pattern, level)

    # No matches - pass through
    return ("pass", "No matching patterns", None, None)
