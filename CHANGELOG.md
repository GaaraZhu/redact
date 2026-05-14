# Changelog

## [0.6.3] — 2026-05-14

### Fixed
- MCP proxy now fails closed when a `tools/call` response exceeds `max_payload_bytes`: returns a JSON-RPC error to the agent instead of forwarding the payload unredacted.
- `DISCLAIMER.md` product name corrected from `redact` to `gate`.
- Curl regex in `rewrite_curl_in_shell_str` now compiled once via `OnceLock` instead of per call.

### Security
- `THREAT-MODEL.md` documents the `max_payload_bytes` behaviour and the MCP `resources/read` passthrough gap.

### CI
- Added `cargo audit` (rustsec/audit-check) to the CI matrix.

## [0.6.2]

- Gate 1 column allowlist: skip name-based PII redaction for explicitly allowlisted columns.
- `gate scan --verbose` now shows all categories, not just the top 3.

## [0.6.1]

- `gate scan` accepts CSV input from GUI database clients (e.g. TablePlus export format).

## [0.6.0]

- Initial public release of the `gate scan` subcommand for schema PII classification.
- MCP proxy (`gate mcp`) intercepts `tools/call` responses and redacts PII via Gate 2.

## [0.5.x]

- Hook path performance improvements.
- `gate init --harness opencode` support.
- `gate validate` subcommand for config pre-flight checks.

## [0.4.x and earlier]

Early development. Core Gate 1 (SQL tokenizer) and Gate 2 (redactor) pipeline established.
