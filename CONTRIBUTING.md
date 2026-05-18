# Contributing to gate

Bug reports, feature requests, and pull requests are welcome.

## Before you start

For significant changes, open an issue first to discuss the proposal. Small bug fixes and documentation improvements can go straight to a PR.

## Setup

```bash
git clone https://github.com/GaaraZhu/gate
cd gate
cargo build
cargo test --all
```

Rust stable is required. No other dependencies beyond the Cargo workspace.

## Local database containers

`dev/docker-compose.yml` provides test databases seeded with PII demo data:

```bash
cd dev && docker compose up -d
```

| Service | Port | Credentials |
|---|---|---|
| PostgreSQL 16 | 5432 | user `gate`, password `gate`, database `gatepay` |
| MySQL 8 | 3306 | user `gate`, password `gate`, database `gatepay` |
| MariaDB 11 | 3307 | user `gate`, password `gate`, database `gatepay` |

All three are seeded with the same `users` and `transactions` tables containing realistic PII (names, emails, phone numbers, card numbers).

## Pre-commit checklist

Run all three from the workspace root and fix any failures before pushing:

```bash
cargo fmt --all
cargo clippy -- -D warnings
cargo test --all
```

CI enforces all three plus `cargo audit`. A PR that fails any of these will not be merged.

## Safety rules for redaction changes

If you touch `common/redactor.rs`, `gate1/lib.rs`, or `mcp/intercept.rs`:

1. **False-negative scan** — identify any PII that could slip through the changed logic.
2. **Test coverage** — add a test that fails before your fix and passes after.
3. **Non-negotiables** — re-read the Non-negotiables section in `CLAUDE.md` and verify each item still holds.

Gate 2 false negatives (PII reaching the model) are treated as security bugs, not ordinary bugs.

## Filing issues

Use GitHub Issues. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.
