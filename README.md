<p align="center">
  <img src="assets/banner.png" alt="gate" width="600">
</p>

<p align="center">
  <strong>A deterministic privacy boundary between your data and AI.<br>Intercepts query results before the model sees them — rule-driven, reproducible, and audit-ready.</strong>
</p>

<p align="center">
  <a href="https://github.com/GaaraZhu/gate/actions"><img src="https://github.com/GaaraZhu/gate/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://github.com/GaaraZhu/gate/releases"><img src="https://img.shields.io/github/v/release/GaaraZhu/gate" alt="Release"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/GaaraZhu/homebrew-gate"><img src="https://img.shields.io/badge/homebrew-tap-orange?logo=homebrew" alt="Homebrew"></a>
</p>

---

AI coding agents that access internal data sources can inadvertently exfiltrate PII — whether querying a database or calling an internal API. A single `SELECT *` or `curl` against an internal service can expose emails, SSNs, and payment data directly into the model's context window — and from there into logs, prompts, and training pipelines. `gate` stops this without requiring any changes to the AI's prompts or tools.

## Demo

**Claude Code** — the agent asked for all users in plain English; `gate` intercepted the query and returned all columns with `full_name` and `email` masked before they reached the model context.

![gate blocking PII in a Claude Code session using tkpsql](assets/demo-claude-code.jpg)

**OpenCode** — same query, same two-gate redaction pipeline, different harness. The `full_name` and `email` columns are replaced with `[PII:name]` and `[PII:email]` before the model sees the result.

![gate blocking PII in an opencode session using tkpsql](assets/demo-opencode.jpg)

## Quickstart

1. **Install gate**

   ```bash
   # Homebrew (recommended)
   brew tap GaaraZhu/gate && brew install gate

   # Or via cargo
   cargo install --git https://github.com/GaaraZhu/gate
   ```

2. **Create your config** (opens `~/.config/gate/config.yaml` in your editor):

   ```bash
   gate config
   ```

3. **Register the hook** with your agent harness:

   ```bash
   # Claude Code
   gate init

   # OpenCode — global
   gate init --harness opencode
   # OpenCode — project-scoped
   gate init --harness opencode --scope project
   ```

   Restart your opencode session after running `gate init` to load the plugin.

4. **Start your AI session** — `gate` intercepts query commands automatically. No changes to your prompts or tools required.

Run `gate validate` to confirm your config is valid before the first session.

## How it works

`gate` integrates with your agent harness as a transparent rewrite hook. Every Bash command the AI tries to run passes through `gate hook` first. Commands that match a configured tool are silently rewritten to `gate run -- <original command>`, which applies two sequential detection gates and returns sanitized JSON. The AI sees the same JSON structure as before, with PII values replaced by typed placeholders like `[PII:email]`.

The rewrite is **enforcing** in both supported harnesses — the AI cannot bypass it:

- **Claude Code** — registered as a [`PreToolUse` hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in `~/.claude/settings.json`; Claude Code replaces the command via `updatedInput` before running it.
- **OpenCode** — a TypeScript plugin's `tool.execute.before` handler mutates `output.args.command` before the subprocess spawns; same guarantee as Claude Code.

Humans and CI scripts running outside the agent harness are unaffected — no wrapper scripts are installed on PATH.

```
AI asks to run: tkpsql query --sql "SELECT * FROM users"
                        │
         harness hook fires (PreToolUse / tool.execute.before)
                        │
              gate hook rewrites to: gate run -- tkpsql query --sql "..."
                        │
         ┌──────────────┴──────────────┐
         │ Gate 1: SQL inspection      │  SELECT * → no column hints, defer to Gate 2
         │ Gate 2: Value scanning      │  regex + column-name heuristics + Luhn check
         └──────────────┬──────────────┘
                        │
         {"id": 1, "full_name": "[PII:name]", "email": "[PII:email]", "status": "active", ..., "_gate_summary": {...}}
```

**What the tool returns** (never reaches the model):
```json
{
  "rows": [
    {
      "id": 1,
      "full_name": "Alice Johnson",
      "email": "alice.johnson@example.com",
      "status": "active",
      "created_at": "2023-01-15 10:30:00",
      "last_login_at": "2024-05-06 14:22:00"
    },
    ...
  ],
  "count": 5
}
```

**What the AI sees**:
```json
{
  "rows": [
    {
      "id": 1,
      "full_name": "[PII:name]",
      "email": "[PII:email]",
      "status": "active",
      "created_at": "2023-01-15 10:30:00",
      "last_login_at": "2024-05-06 14:22:00"
    },
    ...
  ],
  "count": 5,
  "_gate_summary": {
    "redacted": 10,
    "types": ["name", "email"],
    "warnings": ["SELECT * used — consider listing columns explicitly"]
  }
}
```

## Supported commands

Any command that returns JSON can be configured as a `gate` target — database clients, internal API calls via `curl`, or any other tool your AI agent uses to fetch data. The AI sees the same structured response it always did, with PII values replaced in-place.

The `tk*` commands are managed by [toolkit](https://github.com/scott-abernethy/toolkit), a credential-injecting CLI wrapper for database clients. `gate` works with any JSON-returning command — toolkit is not required.

| Command | Type | Status |
|---|---|---|
| `tkpsql` | PostgreSQL (toolkit-managed) | Supported |
| `tkmsql` | MS SQL Server (toolkit-managed) | Supported |
| `tkdbr` | Databricks (toolkit-managed) | Supported |
| `curl` | Internal API / HTTP data source | Planned |
| Raw DB clients (`psql`, `mysql`, …) | Direct database access | Planned |

## Configuration

Config lives at `~/.config/gate/config.yaml` (override with `GATE_CONFIG`).

```yaml
# Set to false to disable all PII redaction (or use GATE_DISABLED=1 for a session).
enabled: true

tools:
  tkpsql:
    sql_arg: "--sql"
  tkmsql:
    sql_arg: "--sql"
  tkdbr:
    sql_arg: "--sql"

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
  wildcard_policy: warn   # warn | reject — applies when the AI uses SELECT * (no explicit column list)

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

  # Values matched below this threshold are flagged in _gate_summary but not redacted.
  confidence_threshold: 0.8

  # Redaction placeholder template; {type} is replaced with the pattern name.
  redaction: "[PII:{type}]"

  include_summary: true

  # When true, redacted values include a deterministic 8-char hex suffix derived
  # from the original value (e.g. [PII:email:7f83b165]).  The same raw value always
  # produces the same suffix, so the AI can correlate records across rows without
  # seeing the underlying data.  Set hash_salt to a fixed secret for consistent
  # hashes across runs; leave empty for zero-config determinism.
  hash_values: false
  hash_salt: ""
```

## Commands

| Command | Purpose |
|---|---|
| `gate init [--harness claude-code\|opencode] [--scope global\|project]` | Register the hook in the agent harness. `claude-code` (default) writes `~/.claude/settings.json`; `opencode` writes a TypeScript plugin at the chosen scope. |
| `gate uninstall` | Remove the hook, config directory, and gate-generated opencode plugins (with confirmation) |
| `gate enable` | Enable PII redaction (sets `enabled: true` in config) |
| `gate disable` | Disable PII redaction (sets `enabled: false` in config) |
| `gate config` | Create and edit the config file |
| `gate list` | Show configured tools and their SQL flags |
| `gate validate` | Check config for errors and warnings |
| `gate version` | Print version |
| `gate run -- <cmd>` | *(internal)* Run a command through the gate pipeline — invoked by the hook, not directly |
| `gate hook` | *(internal)* Hook entry point — invoked by the harness, not directly |

To disable redaction for a single shell session without editing the config file, set the `GATE_DISABLED` environment variable:

```bash
export GATE_DISABLED=1   # disable for this session
unset GATE_DISABLED      # re-enable
```

The env var takes precedence over the config file, so it works even when `enabled: true` is set.

## Security scope

`gate` intercepts the output of configured tools and redacts PII before it reaches the model context. It is not a sandbox — it only applies to commands explicitly listed under `tools:` in config. Commands outside that list pass through the harness unchanged.

**What gate covers:** PII in query results returned by configured tools.

**What gate does not cover:**
- Commands not listed in `tools:` — the AI can invoke them freely
- Write operations (INSERT, UPDATE, DELETE) — gate does not inspect or block them
- Credential exposure — gate holds no credentials; that is the responsibility of the underlying tool

For a stronger boundary, combine gate with harness-level tool restrictions (e.g. limiting which Bash commands the agent is permitted to run) and database-level read-only roles.

## Output format

Redacted output preserves the original JSON structure. PII values are replaced with `[PII:<type>]` placeholders. A `_gate_summary` field is appended reporting what was redacted. All other fields (including `count`, `rows`, etc.) are passed through from the underlying tool unchanged.

```json
{
  "rows": [{"id": 1, "email": "[PII:email]", "ssn": "[PII:ssn]"}],
  "count": 1,
  "_gate_summary": {"redacted": 2, "types": ["email", "ssn"], "warnings": []}
}
```

With `hash_values: true`, each placeholder gains an 8-char hex suffix derived from the original value. The same raw value always produces the same suffix, so the AI can join or deduplicate across rows without ever seeing the underlying data.

```json
{
  "rows": [{"id": 1, "email": "[PII:email:7f83b165]", "ssn": "[PII:ssn:3c2a1b0e]"}],
  "count": 1,
  "_gate_summary": {"redacted": 2, "types": ["email", "ssn"], "warnings": []}
}
```

Error responses from the underlying tool pass through unchanged.

## Uninstallation

```bash
gate uninstall
brew uninstall gate
```

`gate uninstall` removes everything gate added to your system — the hook from `~/.claude/settings.json`, the config directory at `~/.config/gate/`, and any gate-generated opencode plugins. It shows you exactly what will be deleted and asks for confirmation before touching anything.

## Troubleshooting

**Commands are passing through unredacted.**
Run `gate validate` to check for config errors. Confirm the hook is registered by checking that `~/.claude/settings.json` contains a `gate hook` entry — if not, re-run `gate init`. Then restart your agent session so the harness picks up the updated settings.

**`gate: command not found` inside the agent session.**
The shell PATH inside the harness may differ from your login shell. Find the full path with `which gate` in a normal terminal, then set `GATE_BIN` to that path or add the directory to the harness's PATH in your shell profile.

**OpenCode isn't intercepting commands after `gate init`.**
The plugin is loaded at session start — restart your opencode session after running `gate init --harness opencode`.

**Config file not found.**
Run `gate config` to create `~/.config/gate/config.yaml`. If you store the config elsewhere, set `GATE_CONFIG=/path/to/config.yaml` in your environment.

**Non-PII values are being redacted (false positives).**
Raise `confidence_threshold` (e.g. to `0.9`) to reduce over-redaction, or narrow the regex for the offending pattern in the `patterns` block. Run `gate validate` after editing to catch syntax errors.

**`_gate_summary` warns about `SELECT *`.**
Gate 1 can't infer column types from a wildcard query, so every value is passed to Gate 2's regex scanner. Use an explicit column list (`SELECT id, status, created_at FROM users`) to skip the warning and avoid scanning non-PII columns.

## Roadmap

**GitHub Copilot CLI** — deferred to a future release. Copilot CLI's `preToolUse` hook only supports deny-with-suggestion (no transparent rewrite), which makes the integration *advisory* — strictly safer than no hook, but the AI could in principle ignore the suggested rewrite. We're holding the integration until either Copilot CLI gains an `updatedInput` equivalent or the user demand justifies shipping the advisory-only mode.

## Contributing

Bug reports and pull requests are welcome. For significant changes, open an issue first to discuss the proposal. See [CLAUDE.md](CLAUDE.md) for the full dev setup and pre-commit checklist.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md).
