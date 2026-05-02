# Dev environment

Local Postgres setup for testing `redact` end-to-end against real data.

`psql-json` is a thin wrapper around `psql` that outputs a JSON array — it stands in for `tkpsql`/`tkdbr` in a real deployment. The hook flow is identical: the AI calls `psql-json`, the `PreToolUse` hook intercepts and rewrites to `redact run -- psql-json ...`, and the model sees only the redacted JSON.

## Prerequisites

- Docker (with the `docker compose` plugin)
- Rust toolchain (`cargo`)
- `psql` client (`brew install libpq` on macOS)

## Quick start

```sh
./dev/setup.sh
```

Follow the printed instructions. In short:

```sh
export PATH="$(pwd)/target/release:$(pwd)/dev:$PATH"
export REDACT_CONFIG="$(pwd)/dev/config.yaml"

redact init        # register the hook in ~/.claude/settings.json (run outside Claude Code)
```

Restart Claude Code so the hook takes effect.

## Manual smoke tests (no hook)

```sh
# Raw output — PII fully visible
psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

# Through redact — PII replaced with typed placeholders
redact run -- psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

# Joins work fine; Gate 2 catches PII regardless of table
redact run -- psql-json --sql "
  SELECT u.email, u.phone, o.product, o.amount
  FROM users u JOIN orders o ON o.user_id = u.id"

# SELECT * is rejected by Gate 1 (wildcard_policy: reject)
redact run -- psql-json --sql "SELECT * FROM users"

# Allow SELECT * by setting wildcard_policy: warn in config, then:
redact run -- psql-json --sql "SELECT * FROM orders"
```

## Full hook demo inside Claude Code

With `redact init` done and Claude Code restarted, ask the AI:

> Run `psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"`

The hook fires transparently. Claude sees:

```json
{
  "rows": [
    { "id": 1, "first_name": "[PII:name]", "email": "[PII:email]", "ssn": "[PII:ssn]", "credit_card": "[PII:credit_card]" },
    ...
  ],
  "_redact_summary": { "redacted": 40, "types": ["credit_card", "email", "name", "ssn"], "warnings": [] }
}
```

## Database

| Table    | Columns |
|----------|---------|
| `users`  | id, first_name, last_name, email, phone, ssn, dob, address, credit_card, plan |
| `orders` | id, user_id, product, amount, status, created_at |

All data is synthetic. SSNs use the `000-xx-xxxx` prefix (never issued). Credit cards are well-known Luhn-valid test vectors.

## Tear down

```sh
docker compose -f dev/docker-compose.yml down        # stop, keep data
docker compose -f dev/docker-compose.yml down -v     # stop and delete volume
```
