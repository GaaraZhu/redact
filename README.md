# redact

PII-filtering CLI that transparently intercepts AI agent query commands and redacts sensitive data before it reaches the model context.

AI coding agents querying production databases can inadvertently exfiltrate PII. A single `SELECT *` against a users table exposes emails, SSNs, and payment data directly into the model's context window — and from there into logs, prompts, and training pipelines. `redact` stops this without requiring any changes to the AI's prompts or query tools.

## Demo

A Claude Code session querying a local Postgres database via `tkpsql`. The agent asked for all users in plain English; `redact` intercepted the query and returned all columns — but masked the values of `email` and `credit_card` with `[PII:email]` and `[PII:credit_card]` before they reached the model context.

![redact blocking PII in a Claude Code session using tkpsql](docs/demo-tkpsql.jpg)

## How it works

`redact` registers a [`PreToolUse` hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in the agent harness. Every Bash command the AI tries to run passes through `redact hook` first. Commands that match a configured tool are silently rewritten to `redact run -- <original command>`, which applies two sequential detection gates and returns sanitized JSON. The AI sees the same JSON structure as before, with PII values replaced by typed placeholders like `[PII:email]`.

Humans and CI scripts running outside the agent harness are unaffected — no wrapper scripts are installed on PATH.

```
AI asks to run: tkpsql query --sql "SELECT * FROM users"
                        │
              PreToolUse hook fires
                        │
              redact hook rewrites to: redact run -- tkpsql query --sql "..."
                        │
         ┌──────────────┴──────────────┐
         │ Gate 1: SQL inspection      │  SELECT * → no column hints, defer to Gate 2
         │ Gate 2: Value scanning      │  regex + column-name heuristics + Luhn check
         └──────────────┬──────────────┘
                        │
         {"id": 1, "username": "alice", ..., "email": "[PII:email]", "credit_card": "[PII:credit_card]", "_redact_summary": {...}}
```

## Supported tools

`redact` currently supports tools that **output JSON natively**. The AI sees the same structured response it always did, with PII values replaced in-place.

| Tool | Type | Status |
|---|---|---|
| `tkpsql` | PostgreSQL ([toolkit](https://github.com/scott-abernethy/toolkit)-managed) | Supported |
| `tkdbr` | DynamoDB ([toolkit](https://github.com/scott-abernethy/toolkit)-managed) | Supported |
| `psql` | PostgreSQL (raw client) | Planned — see roadmap |
| `mysql` | MySQL (raw client) | Planned — see roadmap |

Raw clients like `psql` and `mysql` output plain text by default, not JSON. Support is planned via automatic SQL rewriting: `redact` will wrap the query in database-native JSON functions (`json_agg`/`JSON_ARRAYAGG`) before spawning the subprocess — no wrapper binaries required.

![Future: redact blocking PII via psql with SQL rewrite](docs/demo-psql.jpg)

> **Roadmap.** The screenshot above shows a dev preview of `psql` support coming in the next release. `redact` will rewrite `SELECT * FROM users` into `SELECT json_agg(row_to_json(_r)) FROM (SELECT * FROM users) _r`, produce the same JSON shape as `tkpsql`, and apply both gates as today. Non-`SELECT` statements (`\d`, `COPY`, DML) will fail closed rather than forward unredacted output.

## Installation

```bash
# Homebrew (recommended)
brew tap GaaraZhu/redact
brew install redact

# Or via cargo
cargo install --git https://github.com/GaaraZhu/redact

# Create and edit your config
redact config
```

Then register the hook with your agent harness:

**Claude Code** ([claude.ai/code](https://claude.ai/code)) — transparent rewrite; the harness silently runs `redact run -- <your command>`:

```bash
redact init                         # writes ~/.claude/settings.json
```

**opencode** ([opencode.ai](https://opencode.ai)) — transparent rewrite via a TypeScript plugin that mutates `output.args.command` before the subprocess spawns (same enforcing guarantee as Claude Code):

```bash
redact init --harness opencode              # global: ~/.config/opencode/plugin/redact.ts
redact init --harness opencode --scope project  # project: ./.opencode/plugin/redact.ts
```

Restart your opencode session after running `redact init` to load the plugin.

> **Roadmap — additional harnesses.**
> - **GitHub Copilot CLI** — deferred to a future release. Copilot CLI's `preToolUse` hook only supports deny-with-suggestion (no transparent rewrite), which makes the integration *advisory* — strictly safer than no hook, but the AI could in principle ignore the suggested rewrite. We're holding the integration until either Copilot CLI gains an `updatedInput` equivalent or the user demand justifies shipping the advisory-only mode.

## Configuration

Config lives at `~/.config/redact/config.yaml` (override with `REDACT_CONFIG`).

```yaml
# Set to false to disable all PII redaction (or use REDACT_DISABLED=1 for a session).
enabled: true

tools:
  tkpsql:
    sql_arg: "--sql"
  tkdbr:
    sql_arg: "--sql"
  # psql and mysql support is coming in the next release.
  # Raw clients will be supported via automatic SQL rewriting — no wrapper binaries needed.

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
| `redact init [--harness claude-code\|opencode] [--scope global\|project]` | Register the hook in the agent harness. `claude-code` (default) writes `~/.claude/settings.json`; `opencode` writes a TypeScript plugin at the chosen scope. |
| `redact enable` | Enable PII redaction (sets `enabled: true` in config) |
| `redact disable` | Disable PII redaction (sets `enabled: false` in config) |
| `redact config` | Create and edit the config file |
| `redact list` | Show configured tools and their SQL flags |
| `redact validate` | Check config for errors and warnings |
| `redact version` | Print version |

`redact run` and `redact hook` are invoked by the hook machinery, not by users directly.

To disable redaction for a single shell session without editing the config file, set the `REDACT_DISABLED` environment variable:

```bash
export REDACT_DISABLED=1   # disable for this session
unset REDACT_DISABLED      # re-enable
```

The env var takes precedence over the config file, so it works even when `enabled: true` is set.

## Security model

`redact` is one layer in a defense-in-depth stack:

| Layer | Protects against |
|---|---|
| Agent harness sandbox | AI bypassing wrappers by invoking raw clients directly |
| [toolkit](https://github.com/scott-abernethy/toolkit) | Write operations; credential exposure |
| **redact** | PII leaking through query results |

`redact`'s config contains no credentials. For production deployments with sensitive credentials, wrap a toolkit-managed client (`tkpsql`/`tkdbr`) — toolkit handles credential injection.

## Output format

Redacted output preserves the original JSON structure. PII values are replaced with `[PII:<type>]` placeholders. A `_redact_summary` field is appended reporting what was redacted. All other fields (including `count`, `rows`, etc.) are passed through from the underlying tool unchanged.

```json
{
  "rows": [{"id": 1, "email": "[PII:email]", "ssn": "[PII:ssn]"}],
  "count": 1,
  "_redact_summary": {"redacted": 2, "types": ["email", "ssn"], "warnings": []}
}
```

Error responses from the underlying tool pass through unchanged.
