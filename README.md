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

AI agents increasingly access internal databases and APIs through CLI tools, scripts, and MCP servers. Without safeguards, sensitive data such as emails, phone numbers, tax identifiers, and payment details can be unintentionally exposed to LLM context windows.

`gate` intercepts query results before they reach the model and automatically redacts detected PII fields without requiring changes to existing agent workflows or prompts.

> **Note:** Currently, `gate` supports Bash-based tooling. MCP server interception support is planned.

## Demo

The agent asked for all users in plain English; `gate` intercepted the query and returned all columns with `full_name` and `email` masked before they reached the model context.

![gate blocking PII in a Claude Code session using tkpsql](assets/demo-claude-code.jpg)

Also works with OpenCode — see the [full list of supported harnesses](#how-it-works).

## Scan your schema

Before installing the hook, use `gate scan` to assess how much PII your database schema exposes. Pipe the output of a schema query — one that returns `TABLE_NAME` and `COLUMN_NAME` — and gate prints a risk report across every table.

```bash
# PostgreSQL (toolkit-managed)
tkpsql query --sql "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position" | gate scan

# PostgreSQL (direct)
psql -U <user> -h <host> -d <dbname> -c "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position" | gate scan

# Databricks (toolkit-managed)
tkdbr query --conn dev --sql "SELECT TABLE_NAME, COLUMN_NAME FROM system.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '<schema>' ORDER BY TABLE_NAME, COLUMN_NAME" --limit 1000 | gate scan

# MS SQL Server (toolkit-managed)
tkmsql query --sql "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_NAME, ORDINAL_POSITION" | gate scan
```

Example output:

```
Gate PII Scan
───────────────────────────────────────────────────────────

Summary
  Tables scanned         12
  Columns scanned        87

  PII columns            34 (39.1%)
  Non-PII columns        53 (60.9%)

  Risk level         CRITICAL

Detected Categories
───────────────────────────────────────────────────────────
  Names                   8  23.5%
  Contact                 6  17.6%
  Employment              5  14.7%
  Government IDs          4  11.8%
  Financial               3   8.8%

Top Findings
───────────────────────────────────────────────────────────
Names
  users.full_name
  patients.first_name
  patients.last_name
  ... and 5 more

Contact
  users.email
  customers.phone_number
  orders.contact_email

Government IDs
  patients.ssn
  employees.tax_id
  employees.national_id

Note
  Scan detects PII by column name only. Gate 2 also
  catches values in text/JSON columns at query time.

Hint
  Use --verbose to show all detected columns
```

Risk levels: **CRITICAL** (>25% of columns are PII), **HIGH** (>10%), **LOW** (≤10%). The command exits with code 1 if any PII columns are found, making it scriptable in CI audits. Pass `--verbose` to show the full list of detected columns in each category instead of a truncated preview.

> **Note:** `gate scan` detects PII by column name only. A LOW result means your column names look clean — it does not mean the data is safe. Gate 2 additionally inspects values at query time, catching PII in free-text, JSON, and ambiguously-named columns that scan cannot see.

If you have not yet created a config, run `gate config --init-only` first to generate a starter config. No tools need to be configured to use `gate scan` — it only uses built-in column-name detection.

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

`gate` currently covers the **Bash tooling** path: every Bash command the AI tries to run passes through `gate hook` first. Commands that match a configured tool are silently rewritten to `gate run -- <original command>`, which applies two sequential detection gates and returns sanitized JSON. The AI sees the same JSON structure as before, with PII values replaced by typed placeholders like `[PII:email]`.

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

## Built-in PII detection

`gate` ships with two layers of built-in detection that require no configuration.

**Gate 1 — column-name inference from SQL.** When a `sql_arg` is configured, gate parses the SELECT list and marks any column whose name matches a PII pattern as a forced-redact target — even if the raw value would not trigger a regex.

**Gate 2 — value scanning and column-name heuristics.** Every string field in the JSON output is evaluated against regex patterns and a column-name classifier. The classifier tokenises column names (handling `snake_case`, `camelCase`, `PascalCase`, and `UPPER_CASE`) so `userEmail`, `user_email`, and `USER_EMAIL` all resolve to the same detection rule.

### Column-name categories

| Category | Detected columns (representative examples) |
|---|---|
| **Names** | `first_name`, `last_name`, `full_name`, `given_name`, `family_name`, `surname`, `preferred_name`, `middle_name`, `maiden_name`, `salutation`; `<entity>_name` where entity is one of: contact, customer, client, employee, patient, member, owner, recipient, sender, spouse, parent, guardian, manager, sibling, children |
| **Demographics** | `gender`, `sex`, `nationality`, `citizenship` |
| **Government IDs** | `passport`, `license` / `driver_license_number`, `ssn` / `social_security_number`, `national_id`, `tax_number` / `tax_id` / `ird_number`, `visa_number`, `resident_id`, `immigration_id` |
| **Contact** | `email` / `email_address` / `mail`, `phone` / `phone_number` / `mobile`, `fax` |
| **Date of birth** | `dob`, `birth`, `birthday`, `date_of_birth`, `birth_date`, `dateOfBirth` |
| **Location of birth** | `birth_country`, `birth_place`, `birth_city`, `country_of_birth`, `place_of_birth`, `city_of_birth`, `state_of_birth` |
| **Address & location** | `address` / `addr`, `street`, `city`, `state`, `province`, `country`, `postcode`, `zip`, `suburb`, `latitude`, `longitude`, `gps`, `coordinates` |
| **Financial** | `bank_account`, `account_number`, `iban`, `swift`, `routing_number`, `bsb`, `credit_card` / `card_number`, `cvv` / `cvc`, `expiry` |
| **Employment** | `salary`, `wage`, `job_title`, `employee_id`, `staff_id`, `student_id`, `manager_id`, and any `<entity>_id` / `<entity>_number` where entity is: employee, staff, student, member, client, customer, consumer, cust, crm, person, manager, user, device, session, cookie, advertising, external |
| **Health & medical** | `medical`, `health`, `diagnosis`, `prescription`, `disability`, `vaccination`, `vaccine`, `npi` |
| **Online & technical** | `username` / `user_name`, `ip_address`, `mac_address`, `auth_token`, `user_id`, `device_id`, `session_id`, `cookie_id`, `advertising_id` |
| **Biometric** | `biometric`, `fingerprint`, `voiceprint`, `retina`, `face_scan` |
| **Family & relationships** | `next_of_kin`, `emergency_contact`, `spouse_name`, `parent_name`, `guardian_name`, `children_names` |

### Value-based patterns

| Pattern | Detection | Example values caught |
|---|---|---|
| Email address | Regex (confidence 0.95) | `alice@example.com`, `user+tag@company.co.uk` |
| Social Security Number | Regex (confidence 0.90) | `123-45-6789` |
| Phone number | Regex (confidence 0.70) | `+1 555-123-4567`, `(555) 123-4567`, `555.123.4567` |
| Credit / debit card | Regex + [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm) (confidence 1.0) | `4111 1111 1111 1111`, `5500-0055-5555-5559` |

When a column name also matches the denylist, Gate 2 adds a 0.15 confidence boost to any value hit in that column, pushing borderline matches over the redaction threshold.

Add your own columns or patterns in config — see [Configuration](#configuration) below.

## Supported commands

Any command that returns JSON can be configured as a `gate` target — database clients, internal API calls via `curl`, or any other tool your AI agent uses to fetch data. The AI sees the same structured response it always did, with PII values replaced in-place.

The `tk*` commands are managed by [toolkit](https://github.com/scott-abernethy/toolkit), a credential-injecting CLI wrapper for database clients. `gate` works with any JSON-returning command — toolkit is not required.

| Command | Type | Notes |
|---|---|---|
| `tkpsql` | PostgreSQL (toolkit-managed) | `sql_arg: "--sql"` |
| `tkmsql` | MS SQL Server (toolkit-managed) | `sql_arg: "--sql"` |
| `tkdbr` | Databricks (toolkit-managed) | `sql_arg: "--sql"` |
| `psql` | PostgreSQL (direct) | `sql_arg: "-c"`, `extra_args: ["--csv"]`, `pipe: "python3 ..."` — gate injects `--csv` automatically and converts output to JSON |
| `mysql` | MySQL (direct) | `sql_arg: "-e"` |
| `curl` | HTTP data sources | `pipe: "jq -c ."` — wraps output through jq so Gate 2 receives JSON |
| Any JSON-returning command | — | Add it to `tools:` in config |

## Configuration

Config lives at `~/.config/gate/config.yaml` (override with `GATE_CONFIG`).

```yaml
# Set to false to disable all PII redaction (or use GATE_DISABLED=1 for a session).
enabled: true

# Tools whose Bash invocations are intercepted and piped through `gate run`.
# Only tools listed here are intercepted; everything else passes through unchanged.
tools:
  tkpsql:
    sql_arg: "--sql"   # Gate 1 parses this SQL to extract column names for targeted redaction
  tkdbr:
    sql_arg: "--sql"
  tkmsql:
    sql_arg: "--sql"
  psql:
    sql_arg: "-c"
    extra_args: ["--csv"]   # injected automatically; switches psql to CSV output for the pipe
    pipe: "python3 -c \"import sys,csv,json; r=csv.DictReader(sys.stdin); print(json.dumps(list(r)))\""
  mysql:
    sql_arg: "-e"
  curl:
    pipe: "jq -c ."   # wraps curl output through jq so Gate 2 always receives JSON

pii:
  action: redact          # redact | warn | reject
  wildcard_policy: warn   # warn | reject — applies when the AI uses SELECT *

  # Add column names beyond the built-in denylist (see Built-in PII detection above).
  # column_names:
  #   - secret_token
  #   - api_key

  # Override or add PII regex patterns.
  # patterns:
  #   internal_id:
  #     regex: '\bEMP-\d{6}\b'
  #     confidence: 0.85

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
| `gate config [--init-only]` | Create and edit the config file. `--init-only` creates `~/.config/gate/config.yaml` without opening the editor — useful in scripts. |
| `gate list` | Show configured tools and their SQL flags |
| `gate validate` | Check config for errors and warnings |
| `gate version` | Print version |
| `gate scan [--verbose]` | Pipe schema query output (`SELECT TABLE_NAME, COLUMN_NAME ...`) into this to get a PII risk report across all tables. `--verbose` shows all detected columns without truncation. Exits 1 if any PII columns are found — scriptable in CI audits. |
| `gate run [--verbose] [-- <cmd>]` | Run a command through the redaction pipeline, or pipe JSON from stdin for direct Gate 2 inspection. Normally invoked by the hook; run manually to test. `--verbose` prints each field's Gate 2 decision to stderr. |
| `gate hook` | *(internal)* Hook entry point — invoked by the harness, not directly |

To disable redaction for a single shell session without editing the config file, set the `GATE_DISABLED` environment variable:

```bash
export GATE_DISABLED=1   # disable for this session
unset GATE_DISABLED      # re-enable
```

The env var takes precedence over the config file, so it works even when `enabled: true` is set.

## Security scope

`gate` intercepts the output of configured tools and redacts PII before it reaches the model context. It is not a sandbox — it only applies to commands explicitly listed under `tools:` in config. Commands outside that list pass through the harness unchanged.

**What gate covers:**

PII in query results returned by configured tools.

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

**Certain fields are not being masked (false negatives).**

Run `gate run --verbose -- <your-command>` to see exactly why each field was passed or redacted. For each string field, verbose mode prints which step triggered (forced column, column-name classifier, Luhn, regex) or `passed (no match)` if nothing fired. You can also pipe a sample payload directly: `echo '<json>' | gate run --verbose`. Common fixes: add the column name to `column_names:` in config, or lower `confidence_threshold` if a pattern is matching below the threshold.

**`gate run --verbose` shows "input is not JSON — redaction skipped".**

The tool's output is not valid JSON, so Gate 2 cannot inspect it and passes the raw bytes through unchanged. This is expected for tools that return plain text or binary output. If you expect JSON, check the tool's output format — some CLIs require a `--json` or `--output json` flag to produce structured output.

**Non-PII values are being redacted (false positives).**

Raise `confidence_threshold` (e.g. to `0.9`) to reduce over-redaction, or narrow the regex for the offending pattern in the `patterns` block. Run `gate validate` after editing to catch syntax errors.

**`_gate_summary` warns about `SELECT *`.**

Gate 1 can't infer column types from a wildcard query, so every value is passed to Gate 2's regex scanner. Use an explicit column list (`SELECT id, status, created_at FROM users`) to skip the warning and avoid scanning non-PII columns.

## Roadmap

**MCP server interception** — gate currently covers the Bash tooling path (CLI commands the AI runs via the shell). The other common access pattern is MCP: the AI calls a Model Context Protocol server directly, bypassing the shell entirely. MCP support will bring the same two-gate redaction pipeline to MCP tool responses, with no changes required to the MCP server itself.

**GitHub Copilot CLI** — deferred to a future release. Copilot CLI's `preToolUse` hook only supports deny-with-suggestion (no transparent rewrite), which makes the integration *advisory* — strictly safer than no hook, but the AI could in principle ignore the suggested rewrite. We're holding the integration until either Copilot CLI gains an `updatedInput` equivalent or the user demand justifies shipping the advisory-only mode.

## Contributing

Bug reports and pull requests are welcome. For significant changes, open an issue first to discuss the proposal. See [CLAUDE.md](CLAUDE.md) for the full dev setup and pre-commit checklist.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md).
