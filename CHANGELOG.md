# Changelog

## [0.6.9] — 2026-05-16

### Fixed
- `gate mcp` now respects the global `enabled: false` setting (and `GATE_DISABLED`) and proxies untouched when redaction is disabled.
- `gate scan` output table now has consistent column alignment.

## [0.6.8] — 2026-05-16

### Changed
- `gate scan` output refactored for cleaner section layout; dev dataset refreshed.

## [0.6.7] — 2026-05-15

### Added
- `gate scan` reports a `NONE` risk level (bright green) when no PII columns are detected, and hides the *Detected Categories* and *Top Findings* sections in that case.

### CI
- Release builds use the full `~/.cargo/bin/cargo` path to avoid `rustup-init` collisions on `macos-14` runners; `rust-cache` removed from the release workflow.

## [0.6.6] — 2026-05-15

### Added
- `gate scan` natively parses the Databricks SQL Statements API response format, so output from `databricks api post /api/2.0/sql/statements ...` can be piped directly into `gate scan`.

### Fixed
- Removed `suburb`, `city`, `state`, `province`, `country` from the built-in PII column-name list — they generated too many false positives on product/inventory schemas. Gate 2 value patterns are unaffected.

## [0.6.5] — 2026-05-14

### Added
- `databricks` CLI support: `sql_arg: "--json"` plus `json_sql_path: "statement"` extracts the SQL out of the JSON payload before Gate 1 inspection.
- `gate scan` UX polish — bold bright-cyan section headers, redundant sensitivity label dropped from *Top Findings*, singular/plural column-count grammar.

### Fixed
- MCP proxy now fails closed when a `tools/call` response exceeds `max_payload_bytes`: returns a JSON-RPC error to the agent instead of forwarding the payload unredacted.
- `DISCLAIMER.md` product name corrected from `redact` to `gate`.
- Curl regex in `rewrite_curl_in_shell_str` compiled once via `OnceLock` instead of per call.
- `redact_stdin` now propagates stdin read errors instead of swallowing them.

### Docs
- Added `THREAT-MODEL.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- README documents the MCP interception scope (`tools/call` only) and Databricks CLI support.

### CI
- Added `cargo audit` (rustsec/audit-check) to the matrix.

## [0.6.4] — 2026-05-13

### Added
- Column allowlist (`gate allowlist add/remove/list`) — listed columns skip name-based redaction. Value-based checks (Luhn, regex patterns) still apply.
- `gate scan` accepts CSV input from GUI database clients (e.g. TablePlus export format).
- `gate scan --verbose` shows all categories, not just the top 3.

## [0.6.3] — 2026-05-12

### Added
- Initial column allowlist plumbing in Gate 1.

## [0.6.2]

- `gate scan --verbose` foundational support for full category listing.

## [0.6.1]

- `gate scan` accepts CSV input from GUI database clients (early form).

## [0.6.0]

- Initial public release of the `gate scan` subcommand for schema PII classification.
- MCP proxy (`gate mcp`) intercepts `tools/call` responses and redacts PII via Gate 2.

## [0.5.x]

- Hook path performance improvements.
- `gate init --harness opencode` support.
- `gate validate` subcommand for config pre-flight checks.

## [0.4.x and earlier]

Early development. Core Gate 1 (SQL tokenizer) and Gate 2 (redactor) pipeline established.
