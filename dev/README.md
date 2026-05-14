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
psql-json --sql "SELECT id, full_name, email, status FROM users"

# Through gate — PII replaced with typed placeholders
gate run -- psql-json --sql "SELECT id, full_name, email, status FROM users"

# Non-PII columns pass through untouched
gate run -- psql-json --sql "SELECT id, status, created_at FROM users"

# SELECT * is rejected by Gate 1 (wildcard_policy: reject)
gate run -- psql-json --sql "SELECT * FROM users"
```

## Full hook demo inside Claude Code

With `gate init` done and Claude Code restarted, ask the AI:

> Run `psql-json --sql "SELECT id, full_name, email, status FROM users"`

The hook fires transparently. Claude sees:

```json
{
  "rows": [
    { "id": 1, "full_name": "[PII:name]", "email": "[PII:email]", "status": "active" },
    { "id": 2, "full_name": "[PII:name]", "email": "[PII:email]", "status": "active" }
  ],
  "_gate_summary": { "redacted": 10, "types": ["email", "name"], "warnings": [] }
}
```

## Database

| Table   | Columns                                                      |
|---------|--------------------------------------------------------------|
| `users` | id, full_name, email, status, created_at, last_login_at      |

`full_name` and `email` are the PII columns. All data is synthetic.

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
    "postgres-local": {
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

> Use the `postgres-local` MCP tool to run `SELECT id, full_name, email, status FROM users`

The AI sees raw PII — `full_name` and `email` are unredacted. To protect this path, register the server through `gate mcp` (see `gate init --mcp` or `gate init --wrap-mcp` in the main README).

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
