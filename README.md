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

`gate` intercepts query results before they reach the model and automatically redacts detected PII fields without requiring changes to existing agent workflows or prompts. It covers both access paths agents use: **Bash commands** (via a harness hook) and **MCP server calls** (via a wrap-style stdio proxy).

## Demo

The demo walks through three steps:

1. `gate scan` detecting PII columns across the schema before any query runs
2. An agent querying the transactions table with gate disabled — `card_number` fully visible
3. The same queries with gate enabled — `card_number` redacted across both MCP and Bash paths

![gate intercepting PII before it reaches the model](assets/demo.gif)

Also works with OpenCode — see [How it works](#how-it-works) for all supported harnesses.

> For the design rationale, threat-model walkthrough, and detection-pipeline deep dive, read [**Introducing gate**](https://gaarazhu.github.io/introducing-gate/).

## Scan your schema

Before installing the hook, use `gate scan` to assess how much PII your database schema exposes. Pipe the output of a schema query — one that returns `TABLE_NAME` and `COLUMN_NAME` — and gate prints a risk report across every table. No config is required; `gate scan` only uses built-in column-name detection. If you haven't created a config yet, run `gate config --init-only` first.

```bash
# PostgreSQL (toolkit-managed)
tkpsql query --sql "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'public' ORDER BY TABLE_NAME, ORDINAL_POSITION" | gate scan

# PostgreSQL (direct)
psql -U <user> -h <host> -d <dbname> -c "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'public' ORDER BY TABLE_NAME, ORDINAL_POSITION" | gate scan

# Databricks (toolkit-managed)
tkdbr query --conn dev --sql "SELECT TABLE_NAME, COLUMN_NAME FROM system.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '<schema>' ORDER BY TABLE_NAME, COLUMN_NAME" --limit 1000 | gate scan

# Databricks (native CLI)
databricks api post /api/2.0/sql/statements --profile <profile> --json "{\"statement\": \"SELECT TABLE_NAME, COLUMN_NAME FROM system.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '<schema>' LIMIT 1000\", \"warehouse_id\": \"<warehouse_id>\"}" | gate scan

# MS SQL Server (toolkit-managed)
tkmsql query --sql "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_NAME, ORDINAL_POSITION" | gate scan
```

Risk level is weighted by category sensitivity — one SSN column matters more than twenty address columns. The command exits with code 1 if any PII columns are found, making it scriptable in CI audits. Pass `--verbose` to show all detected columns, or `--json` for machine-readable output.

| Sensitivity | Categories | Risk floor |
|-------------|-----------|------------|
| **Critical** | Government IDs, Health & medical, Financial, Biometric | **HIGH** always; **CRITICAL** if ≥3 columns or >10% of schema |
| **Elevated** | Contact, Names, Date of birth, Location of birth, Family & relationships, Employment | **HIGH** if >5% of schema; **CRITICAL** if >25% |
| **Standard** | Address & location, Online & technical, Demographics | **HIGH** if >25% of schema |

> **Note:** `gate scan` detects PII by column name only. A LOW result means your column names look clean — it does not mean the data is safe. Gate 2 additionally inspects values at query time, catching PII in free-text, JSON, and ambiguously-named columns that scan cannot see.

### Handling false positives

Some column names may be flagged incorrectly — for example `city` in a `products` table or `bank_account_id` used as a foreign key. Run `gate scan --review` after the report to triage these interactively:

```
Allowlist false positives
───────────────────────────────────────────────────────────
Columns to allowlist (space/comma-separated), or Enter to skip: city state
Columns to remove (space/comma-separated), or Enter to keep all:

Added 2 column(s): city, state
Config updated: /Users/alice/.config/gate/config.yaml
```

Allowlisted columns skip **name-based** redaction only. Gate 2 still checks their values against regex patterns and the Luhn credit-card algorithm. Manage the list directly with `gate allowlist add/remove/list`.

## Quickstart

1. **Install gate**

   ```bash
   # Homebrew — macOS and Linux (recommended)
   brew tap GaaraZhu/gate && brew install gate

   # cargo binstall — downloads a prebuilt binary for your platform
   cargo binstall gate

   # Direct download — grab the binary for your platform from the releases page
   # https://github.com/GaaraZhu/gate/releases

   # Build from source
   cargo install --git https://github.com/GaaraZhu/gate
   ```

2. **Create your config** (opens `~/.config/gate/config.yaml` in your editor):

   ```bash
   gate config
   ```

3. **Register the hook** with your agent harness:

   ```bash
   # Claude Code — global (applies to all projects)
   gate init
   # Claude Code — project-scoped (.claude/settings.json in repo root)
   gate init --scope project

   # OpenCode — global
   gate init --harness opencode
   # OpenCode — project-scoped
   gate init --harness opencode --scope project

   # GitHub Copilot CLI — project-scoped (run from repo root)
   gate init --harness copilot-cli
   ```

   Restart your opencode session after running `gate init` to load the plugin.

   For Copilot CLI, `gate init` writes `.github/hooks/PreToolUse.json` in the current git repository root. The file is gitignored by default — each developer runs `gate init --harness copilot-cli` once in their local clone.

4. *(Optional)* **Register MCP server proxies** for any MCP servers your agent uses.

   If you already have MCP servers configured, wrap them all at once with `--wrap-mcp` (dry-run by default; add `--yes` to apply):

   ```bash
   # Claude Code — wrap all servers in ~/.claude.json (dry-run)
   gate init --wrap-mcp

   # Claude Code — wrap all servers in ./.mcp.json (dry-run)
   gate init --scope project --wrap-mcp

   # Wrap only specific servers
   gate init --wrap-mcp --servers postgres,github

   # Apply
   gate init --wrap-mcp --yes
   gate init --wrap-mcp --servers postgres,github --yes
   gate init --scope project --wrap-mcp --yes

   # OpenCode
   gate init --harness opencode --wrap-mcp --yes

   # Copilot CLI — project-level .mcp.json (dry-run)
   gate init --harness copilot-cli --scope project --wrap-mcp
   # Copilot CLI — user-level ~/.copilot/mcp-config.json (dry-run)
   gate init --harness copilot-cli --wrap-mcp
   ```

   Or register a single server manually:

   ```bash
   # Claude Code — user-level (applies to all projects, written to ~/.claude.json)
   gate init --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

   # Claude Code — project-level (applies to this project only, written to ./.mcp.json)
   gate init --scope project --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

   # OpenCode
   gate init --harness opencode --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

   # Copilot CLI — user-level (~/.copilot/mcp-config.json)
   gate init --harness copilot-cli --mcp postgres --mcp-cmd "uvx mcp-server-postgres"
   # Copilot CLI — project-level (.mcp.json)
   gate init --harness copilot-cli --scope project --mcp postgres --mcp-cmd "uvx mcp-server-postgres"
   ```

   Both approaches register `gate mcp` as a transparent proxy in front of each MCP server so tool results are redacted before reaching the model.

4. **Start your AI session** — `gate` intercepts query commands automatically. No changes to your prompts or tools required.

Run `gate validate` to confirm your config is valid before the first session.

## How it works

`gate` covers two access paths agents use to reach data. The [blog post](https://gaarazhu.github.io/introducing-gate/) has the full walkthrough; the short version:

### Bash tooling path

Every Bash command passes through `gate hook` first. Commands that match a configured tool are silently rewritten to `gate run -- <original command>`, which spawns the subprocess and pipes stdout through the two-gate detection pipeline. The rewrite happens in the harness's pre-tool-execution hook — it is **enforcing** in Claude Code, OpenCode, and GitHub Copilot CLI; the agent cannot bypass it. Humans and CI scripts running outside the harness are untouched.

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
         {"id": 1, "full_name": "[PII:name]", "email": "[PII:email]", ..., "_gate_summary": {...}}
```

### MCP path

`gate mcp` is a transparent stdio proxy registered in the harness as the MCP server. It forwards all JSON-RPC traffic verbatim except `tools/call` responses, which are passed through Gate 2 before reaching the model. No changes to the upstream server are required.

> **Note:** only `tools/call` responses are redacted — `resources/read`, `prompts/get`, and other MCP message types are forwarded without inspection.

```
AI ──tools/call──> gate mcp ──forward──> upstream MCP server
                       │
                       │ <── tools/call response with PII
                       │
                       │ Gate 2 scan + redact
                       │
AI <───redacted result─┘
```

See [Quickstart](#quickstart) step 4 for setup commands (`--wrap-mcp` to convert existing servers, `--mcp` to register one manually).

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

## Security scope

`gate` intercepts the output of configured tools and redacts PII before it reaches the model context. It is not a sandbox — it only applies to commands explicitly listed under `tools:` in config. Commands outside that list pass through the harness unchanged.

**What gate covers:**

PII in query results returned by configured tools.

**What gate does not cover:**
- Commands not listed in `tools:` — the AI can invoke them freely
- Write operations (INSERT, UPDATE, DELETE) — gate does not inspect or block them
- Credential exposure — gate holds no credentials; that is the responsibility of the underlying tool

For a stronger boundary, combine gate with harness-level tool restrictions (e.g. limiting which Bash commands the agent is permitted to run) and database-level read-only roles.

For a full description of the attacker model, detection gaps, and known bypasses, see [THREAT-MODEL.md](THREAT-MODEL.md).

## Documentation

- [Configuration](docs/configuration.md) — full YAML schema and built-in PII detection rules
- [Config file locations](docs/config-locations.md) — where each harness stores hooks and MCP settings
- [Troubleshooting](docs/troubleshooting.md) — common issues and fixes

## Supported tools

Any command that returns JSON can be configured as a `gate` target — database clients, internal API calls via `curl`, or any other tool your AI agent uses to fetch data. The AI sees the same structured response it always did, with PII values replaced in-place.

The `tk*` commands are managed by [toolkit](https://github.com/scott-abernethy/toolkit), a credential-injecting CLI wrapper for database clients. `gate` works with any JSON-returning command — toolkit is not required.

| Command | Type | Notes |
|---|---|---|
| `tkpsql` | PostgreSQL (toolkit-managed) | `sql_arg: "--sql"` |
| `tkmsql` | MS SQL Server (toolkit-managed) | `sql_arg: "--sql"` |
| `tkdbr` | Databricks (toolkit-managed) | `sql_arg: "--sql"` |
| `databricks` | Databricks CLI (native) | `sql_arg: "--json"`, `json_sql_path: "statement"` — extracts SQL from JSON payload before redaction |
| `psql` | PostgreSQL (direct) | `sql_arg: "-c"`, `extra_args: ["--csv"]`, `pipe: "python3 ..."` — gate injects `--csv` automatically and converts output to JSON |
| `mysql` | MySQL (direct) | `sql_arg: "-e"` |
| `curl` | HTTP data sources | `pipe: "jq -c ."` — wraps output through jq so Gate 2 receives JSON |
| Any JSON-returning command | — | Add it to `tools:` in config |

## Commands

| Command | Purpose |
|---|---|
| `gate init [--harness claude-code\|opencode] [--scope global\|project]` | Register the hook in the agent harness. `claude-code` (default) writes `~/.claude/settings.json`; `opencode` writes a TypeScript plugin at the chosen scope. |
| `gate init --wrap-mcp [--servers a,b] [--yes]` | Convert existing MCP servers to `gate mcp` proxies. Dry-run by default; `--yes` to apply. `--servers` limits to a comma-separated list; omit to wrap all. Already-proxied servers are skipped. Respects `--harness` and `--scope`. |
| `gate init --mcp <name> --mcp-cmd <cmd>` | Register a single `gate mcp` proxy. For `claude-code`: `--scope global` (default) writes to `~/.claude.json`; `--scope project` writes to `./.mcp.json`. |
| `gate mcp [--] <upstream-cmd> [args...]` | Run a stdio MCP proxy in front of `<upstream-cmd>`. Intercepts `tools/call` responses and redacts PII before they reach the model. Usually invoked by the harness, not directly. |
| `gate uninstall` | Remove the hook, config directory, and gate-generated opencode plugins (with confirmation) |
| `gate enable` | Enable PII redaction (sets `enabled: true` in config) |
| `gate disable` | Disable PII redaction (sets `enabled: false` in config) |
| `gate protect` *(Unix only)* | Transfer config ownership to root so agents cannot modify it. Run as: `sudo gate protect` |
| `gate unprotect` *(Unix only)* | Restore your ownership of the config. Run as: `sudo gate unprotect` |
| `gate config [--path] [--print] [--init-only]` | Create and edit the config file. `--path` prints the resolved config path and exits. `--print` prints the raw config contents and exits. `--init-only` creates `~/.config/gate/config.yaml` without opening the editor — useful in scripts. |
| `gate list` | Show configured tools and their SQL flags |
| `gate validate` | Check config for errors and warnings |
| `gate version` | Print version |
| `gate scan [--verbose] [--json] [--review]` | Pipe schema query output (`SELECT TABLE_NAME, COLUMN_NAME ...`) into this to get a PII risk report across all tables. `--verbose` shows all detected columns without truncation. `--json` emits results as machine-readable JSON instead of the human-readable report. `--review` enters an interactive triage session after the report to mark false-positive columns and add them to the allowlist. Exits 1 if any PII columns are found — scriptable in CI audits. |
| `gate allowlist add <col> [col...]` | Add column names to the allowlist. Allowlisted columns skip name-based redaction; value-based checks (Luhn, regex) still apply. Changes are written atomically to config. Duplicates are ignored. |
| `gate allowlist remove <col> [col...]` | Remove column names from the allowlist. |
| `gate allowlist list` | Show the current allowlist. |
| `gate run [--verbose] [-- <cmd>]` | Run a command through the redaction pipeline, or pipe JSON from stdin for direct Gate 2 inspection. Normally invoked by the hook; run manually to test. `--verbose` prints each field's Gate 2 decision to stderr. |
| `gate hook` | *(internal)* Hook entry point — invoked by the harness, not directly |

To disable redaction, use `gate disable`. Run `gate enable` to re-enable.

### Config file protection (Unix only)

For a stronger security guarantee, you can transfer ownership of the config file to root:

```bash
sudo gate protect
```

After this, the agent cannot modify the config file — it runs as you, and only root can write to a root-owned file. Any gate command that writes to the config will require `sudo`:

```bash
sudo gate enable
sudo gate disable
sudo gate config
sudo gate allowlist add <col>
```

To restore direct write access:

```bash
sudo gate unprotect
```

This is enforced at the OS level and applies across all harnesses (Claude Code, opencode, Copilot CLI). It is not supported on Windows.

## Uninstallation

```bash
gate uninstall
brew uninstall gate
```

`gate uninstall` removes everything gate added to your system — the hook from `~/.claude/settings.json`, the config directory at `~/.config/gate/`, and any gate-generated opencode plugins. It shows you exactly what will be deleted and asks for confirmation before touching anything.

## Contributing

Bug reports and pull requests are welcome. For significant changes, open an issue first to discuss the proposal. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, pre-commit checklist, and safety rules for redaction changes.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md).
