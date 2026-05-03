# redact

PII-filtering CLI that transparently intercepts AI agent query commands and redacts sensitive data before it reaches the model context.

AI coding agents querying production databases can inadvertently exfiltrate PII. A single `SELECT *` against a users table exposes emails, SSNs, and payment data directly into the model's context window — and from there into logs, prompts, and training pipelines. `redact` stops this without requiring any changes to the AI's prompts or query tools.

## Demo

A Claude Code session querying a local Postgres database. The agent asked for all users in plain English; `redact` intercepted the query and returned all columns — but masked the values of `email` and `credit_card` with `[PII:email]` and `[PII:credit_card]` before they reached the model context.

![redact blocking PII in a Claude Code session](docs/demo.jpg)

## How it works

`redact` registers a [`PreToolUse` hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in the agent harness. Every Bash command the AI tries to run passes through `redact hook` first. Commands that match a configured tool are silently rewritten to route through `redact run`, which applies two sequential detection gates and returns sanitized JSON. The AI sees the same JSON structure as before, with PII values replaced by typed placeholders like `[PII:email]`.

Humans and CI scripts running outside the agent harness are unaffected — no wrapper scripts are installed on PATH.

```
AI asks to run: psql -c "SELECT * FROM users"
                        │
              PreToolUse hook fires
                        │
              redact hook rewrites to: redact run -- psql -c "..."
                        │
         ┌──────────────┴──────────────┐
         │ Gate 1: SQL inspection      │  SELECT * → no column hints, defer to Gate 2
         │ Gate 2: Value scanning      │  regex + column-name heuristics + Luhn check
         └──────────────┬──────────────┘
                        │
         {"id": 1, "username": "alice", ..., "email": "[PII:email]", "credit_card": "[PII:credit_card]", "_redact_summary": {...}}
```

## Installation

```bash
cargo install redact

# Register the PreToolUse hook in Claude Code
# Requires Claude Code: https://claude.ai/code
redact init

# Create and edit your config
redact config
```

## Configuration

Config lives at `~/.config/redact/config.yaml` (override with `REDACT_CONFIG`).

```yaml
tools:
  tkpsql:
    sql_arg: "--sql"
  tkdbr:
    sql_arg: "--sql"
  mysql:
    sql_arg: "-e"
  psql:
    sql_arg: "-c"
  # sqlite3 takes SQL as a positional arg, not a flag:
  # sqlite3:
  #   sql_arg: null

pii:
  # Column names that indicate PII regardless of value content (case-insensitive, substring match).
  # These extend the built-in denylist; they don't replace it.
  column_names:
    - email
    - ssn
    - dob
    - phone
    - npi
    - credit_card
    - card_number
    - cvv
    - passport
    - license_number
    - full_name
    - first_name
    - last_name
    - birthdate

  action: redact          # warn | redact | reject
  wildcard_policy: warn   # warn | reject

  # Built-in patterns (shown here for reference; override by redefining the key).
  # credit_card is handled by the Luhn algorithm (https://en.wikipedia.org/wiki/Luhn_algorithm) and is always confidence 1.0.
  patterns:
    email:
      regex: '[\w.+\-]+@[\w\-]+\.[a-z]{2,}'
      confidence: 0.95
    ssn:
      regex: '\b\d{3}-\d{2}-\d{4}\b'
      confidence: 0.90
    phone:
      regex: '\b(\+1[\s.]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b'
      confidence: 0.70
    ip_address:
      regex: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
      confidence: 0.60
    # Custom pattern example:
    # employee_id:
    #   regex: '\bEMP-\d{6}\b'
    #   confidence: 0.85

  # Added to a pattern's base confidence when the JSON key also matches the column denylist.
  # Final score is capped at 1.0.
  column_name_boost: 0.15

  # Values matched below this threshold are flagged in _redact_summary but not redacted.
  confidence_threshold: 0.8

  # Redaction placeholder template; {type} is replaced with the pattern name.
  redaction: "[PII:{type}]"

  include_summary: true
```

## Commands

| Command | Purpose |
|---|---|
| `redact init` | Register the PreToolUse hook in [Claude Code](https://claude.ai/code) |
| `redact config` | Create and edit the config file |
| `redact list` | Show configured tools and their SQL flags |
| `redact validate` | Check config for errors and warnings |
| `redact version` | Print version |

`redact run` and `redact hook` are invoked by the hook machinery, not by users directly.

## Security model

`redact` is one layer in a defense-in-depth stack:

| Layer | Protects against |
|---|---|
| Agent harness sandbox | AI bypassing wrappers by invoking raw clients directly |
| [toolkit](https://github.com/GaaraZhu/toolkit) | Write operations; credential exposure |
| **redact** | PII leaking through query results |

`redact`'s config contains no credentials. For production deployments with sensitive credentials, wrap a toolkit-managed client (`tkpsql`/`tkdbr`) — toolkit handles credential injection. For raw clients (`mysql`, `psql`), credentials in standard locations (`.my.cnf`, `.pgpass`, env vars) remain reachable to the AI agent; `redact validate` warns when this is the case.

## Output format

Redacted output preserves the original JSON structure. PII values are replaced with `[PII:<type>]` placeholders. An optional `_redact_summary` field reports what was redacted:

```json
{
  "rows": [{"id": 1, "email": "[PII:email]", "ssn": "[PII:ssn]"}],
  "count": 1,
  "_redact_summary": {"redacted": 2, "types": ["email", "ssn"], "warnings": []}
}
```

Error responses from the underlying tool pass through unchanged.
