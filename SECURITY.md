# Security policy

## Supported versions

| Version | Support |
|---|---|
| 0.4.x | ✅ current |
| < 0.4 | best effort |

## Reporting a vulnerability

Please use GitHub's **Private vulnerability reporting** (Security tab →
"Report a vulnerability") rather than a public issue.

Use private reporting for anything exploitable, including:

- A sensitive path the filter allows when it should deny (bypass)
- Symlink or path-canonicalization escapes
- Fail-open behavior on engine errors or timeouts
- Injection through path strings, denial reasons, or the JSON-RPC / ACP
  proxy surface

Please include: the exact path or command, the installed version, the
frontend in use (Claude Code / OpenCode / CLI proxy), and the decision
output you observed.

## What belongs in a normal (public) issue

- A sensitive path or filename pattern not covered yet — with the reason it
  is sensitive
- A false positive you want allowlisted
- Documentation and install problems

## Response goals

We aim to acknowledge private reports within a week and ship a fix or a
clear assessment once the report is reproduced. Denial decisions are
visible in the transcript and logs; if you believe a decision is wrong and
it is not a bypass, a public issue is the fastest path.
