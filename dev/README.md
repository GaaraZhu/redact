# Dev environment

Local Postgres setup for testing `gate` end-to-end against real data.

`psql-json` is a thin wrapper around `psql` that outputs a JSON array — it stands in for `tkpsql`/`tkdbr` in a real deployment. The hook flow is identical: the AI calls `psql-json`, the `PreToolUse` hook intercepts and rewrites to `gate run -- psql-json ...`, and the model sees only the redacted JSON.

## Prerequisites

- Docker runtime and `docker-compose`
  - **Colima**: `brew install colima docker docker-compose && colima start`
  - **Docker Desktop**: compose is bundled
- Rust toolchain (`cargo`)
- `psql` client (`brew install libpq` on macOS)

## Quick start

```sh
./dev/setup.sh
```

Follow the printed instructions. In short:

```sh
export PATH="$(pwd)/target/release:$(pwd)/dev:$PATH"
export GATE_CONFIG="$(pwd)/dev/config.yaml"

gate init        # register the hook in ~/.claude/settings.json (run outside Claude Code)
```

Restart Claude Code so the hook takes effect.

## Manual smoke tests (no hook)

```sh
# Raw output — PII fully visible
psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

# Through gate — PII replaced with typed placeholders
gate run -- psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

# Joins work fine; Gate 2 catches PII regardless of table
gate run -- psql-json --sql "
  SELECT u.email, u.phone, o.product, o.amount
  FROM users u JOIN orders o ON o.user_id = u.id"

# SELECT * is rejected by Gate 1 (wildcard_policy: reject)
gate run -- psql-json --sql "SELECT * FROM users"

# Allow SELECT * by setting wildcard_policy: warn in config, then:
gate run -- psql-json --sql "SELECT * FROM orders"
```

## Full hook demo inside Claude Code

With `gate init` done and Claude Code restarted, ask the AI:

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

## MCP server

`mcp_server.py` exposes the same `gate_demo` database via the Model Context Protocol, so you can test the AI→MCP→Database flow (as opposed to AI→bash→Database).

### Setup

```sh
python3 -m venv dev/.venv
dev/.venv/bin/pip install -r dev/requirements.txt
```

(The `dev/.venv` directory is already in `.gitignore`.)

### Register with Claude Code

Add to your `~/.claude/settings.json` under `mcpServers`:

```json
{
  "mcpServers": {
    "postgres-gate": {
      "command": "/absolute/path/to/gate/dev/.venv/bin/python",
      "args": ["/absolute/path/to/gate/dev/mcp_server.py"]
    }
  }
}
```

Restart Claude Code. The server exposes three tools:

| Tool | Description |
|------|-------------|
| `list_tables` | Names of all tables in the public schema |
| `describe_table(table)` | Column names, types, and nullability |
| `execute_query(sql)` | Run a SELECT; returns rows as JSON |

### Demo (unprotected — PII fully visible to the AI)

Ask Claude:

> Use the `postgres-gate` MCP tool to run `SELECT id, full_name, email, status FROM users`

The AI sees raw PII — `full_name` and `email` are unredacted. This is the flow gate's MCP proxy mode (planned) would protect.

### Override connection settings

```sh
PG_HOST=localhost PG_PORT=5432 PG_DB=gate_demo PG_USER=gate PG_PASS=gate \
  dev/.venv/bin/python dev/mcp_server.py
```

## Tear down

```sh
cd dev && docker-compose down        # stop, keep data
cd dev && docker-compose down -v     # stop and delete volume
```
