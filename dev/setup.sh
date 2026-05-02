#!/usr/bin/env bash
# One-command dev setup: start Postgres, wait for it, build the redact binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV="$ROOT/dev"
BIN="$ROOT/target/release"

echo "==> Starting PostgreSQL..."
docker compose -f "$DEV/docker-compose.yml" up -d

echo -n "==> Waiting for PostgreSQL to be ready"
until docker compose -f "$DEV/docker-compose.yml" exec -T postgres \
    pg_isready -U redact -d redact_demo >/dev/null 2>&1; do
  printf '.'
  sleep 1
done
echo " ready."

echo "==> Building redact (release)..."
cargo build --release --manifest-path "$ROOT/Cargo.toml" -q
echo "    $BIN/redact"

cat <<EOF

==> Setup complete. Run the following in your shell, then follow the steps:

    export PATH="$BIN:$DEV:\$PATH"
    export REDACT_CONFIG="$DEV/config.yaml"

Step 1 — install the hook in Claude Code (run once, outside Claude Code):

    redact init

Step 2 — verify the config is valid:

    redact validate
    redact list

Step 3 — manual smoke test (no hook needed):

    # Raw output — PII visible
    psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

    # Through redact — PII replaced
    redact run -- psql-json --sql "SELECT id, first_name, email, ssn, credit_card FROM users"

    # SELECT * is rejected (wildcard_policy: reject)
    redact run -- psql-json --sql "SELECT * FROM users"

Step 4 — full hook demo inside Claude Code:
    Restart Claude Code so the hook takes effect, then ask:
    "Run psql-json --sql 'SELECT id, first_name, email, ssn, credit_card FROM users'"
    The hook intercepts the call transparently; Claude sees only the redacted JSON.

EOF
