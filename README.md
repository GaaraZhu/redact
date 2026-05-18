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

Before installing the hook, use `gate scan` to assess how much PII your schema exposes. Pipe a `TABLE_NAME, COLUMN_NAME` query into it and gate prints a risk report across every table. No config is required for `gate scan` itself — if you haven't created one yet, run `gate config --init-only` first.

```bash
psql -U <user> -h <host> -d <dbname> -c "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'public' ORDER BY TABLE_NAME, ORDINAL_POSITION" | gate scan
```

See [docs/scan.md](docs/scan.md) for queries against MySQL, MS SQL Server, Databricks, and toolkit-managed clients.

Risk level is weighted by category sensitivity — one SSN column matters more than twenty address columns. Exits with code 1 if any PII columns are found (scriptable in CI). Pass `--verbose` to show all detected columns, or `--json` for machine-readable output.

| Sensitivity | Categories | Risk floor |
|-------------|-----------|------------|
| **Critical** | Government IDs, Health & medical, Financial, Biometric | **HIGH** always; **CRITICAL** if ≥3 columns or >10% of schema |
| **Elevated** | Contact, Names, Date of birth, Location of birth, Family & relationships, Employment | **HIGH** if >5% of schema; **CRITICAL** if >25% |
| **Standard** | Address & location, Online & technical, Demographics | **HIGH** if >25% of schema |

> **Note:** `gate scan` detects PII by column name only. A LOW result means your column names look clean — it does not mean the data is safe. Gate 2 additionally inspects values at query time, catching PII in free-text, JSON, and ambiguously-named columns that scan cannot see.

For false positives (e.g. `city` in a `products` table), run `gate scan --review` to triage interactively and add columns to the allowlist. Allowlisted columns skip **name-based** redaction only — Gate 2 still checks their values against regex patterns and the Luhn algorithm. Manage the list directly with `gate allowlist add/remove/list`.

## Quickstart

1. **Install gate**

   ```bash
   # Homebrew — macOS and Linux (recommended)
   brew tap GaaraZhu/gate && brew install gate

   # cargo binstall — downloads a prebuilt binary
   cargo binstall gate

   # Or grab a binary from the releases page
   # https://github.com/GaaraZhu/gate/releases
   ```

2. **Create your config** (opens `~/.config/gate/config.yaml` in your editor):

   ```bash
   gate config
   ```

3. **Register the hook** with your agent harness:

   ```bash
   # Claude Code (default)
   gate init

   # OpenCode
   gate init --harness opencode

   # GitHub Copilot CLI (project-scoped, run from repo root)
   gate init --harness copilot-cli
   ```

   Add `--scope project` for project-only setup. Restart your opencode session after `gate init` to load the plugin. For Copilot CLI, the generated `.github/hooks/PreToolUse.json` is gitignored by default — each developer runs `gate init --harness copilot-cli` once in their local clone.

4. *(Optional)* **Register MCP server proxies** so `tools/call` responses also pass through gate:

   ```bash
   # Dry-run — shows what would change
   gate init --wrap-mcp

   # Apply
   gate init --wrap-mcp --yes
   ```

   See [docs/mcp.md](docs/mcp.md) for `--servers`, `--scope`, per-harness paths, and manual single-server registration.

5. **Start your AI session** — `gate` intercepts query commands automatically. No changes to your prompts or tools required.

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

`gate mcp` is a transparent stdio proxy registered in the harness as the MCP server. It forwards all JSON-RPC traffic verbatim except `tools/call` responses, which pass through Gate 2 before reaching the model. No changes to the upstream server are required.

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

## Output format

Redacted output preserves the original JSON structure. PII values are replaced with `[PII:<type>]` placeholders. A `_gate_summary` field is appended reporting what was redacted.

```json
{
  "rows": [{"id": 1, "email": "[PII:email]", "ssn": "[PII:ssn]"}],
  "count": 1,
  "_gate_summary": {"redacted": 2, "types": ["email", "ssn"], "warnings": []}
}
```

With `hash_values: true` in config, each placeholder gains an 8-char hex suffix derived from the original value (`[PII:email:7f83b165]`). The same raw value always produces the same suffix, so the AI can join or deduplicate across rows without ever seeing the underlying data. Error responses from the underlying tool pass through unchanged.

## Security scope

`gate` intercepts the output of configured tools and redacts PII before it reaches the model context. It is not a sandbox — it only applies to commands explicitly listed under `tools:` in config.

**Covered:** PII in query results returned by configured tools.

**Not covered:**
- Commands not listed in `tools:` — the AI can invoke them freely
- Write operations (INSERT, UPDATE, DELETE) — gate does not inspect or block them
- Credential exposure — gate holds no credentials; that is the responsibility of the underlying tool

For a stronger boundary, combine gate with harness-level tool restrictions and database-level read-only roles. See [THREAT-MODEL.md](THREAT-MODEL.md) for the full attacker model and known bypasses.

## Supported tools

Any command that returns JSON can be configured as a `gate` target — database clients, internal API calls via `curl`, or any other tool your AI agent uses to fetch data. The AI sees the same structured response it always did, with PII values replaced in-place.

| Command | Type | Notes |
|---|---|---|
| `tkpsql` | PostgreSQL (toolkit-managed) | `sql_arg: "--sql"` |
| `tkmsql` | MS SQL Server (toolkit-managed) | `sql_arg: "--sql"` |
| `tkdbr` | Databricks (toolkit-managed) | `sql_arg: "--sql"` |
| `databricks` | Databricks CLI (native) | `sql_arg: "--json"`, `json_sql_path: "statement"` |
| `curl` | HTTP data sources | `pipe: "jq -c ."` |
| `psql`, `mysql`, `mariadb` | Raw DB clients | **Not enabled by default** — see [Raw database clients](docs/configuration.md#raw-database-clients-opt-in) |

Prefer toolkit commands or MCP servers over raw clients: raw clients typically require credentials on the command line, which lands in the agent's transcript, shell history, and process listing. Toolkit commands ([`tk*`](https://github.com/scott-abernethy/toolkit)) inject credentials from a secrets store; MCP servers hide the connection string entirely. `gate` works with any JSON-returning command — toolkit is not required.

## Commands

```bash
gate --help                    # full subcommand list
gate <subcommand> --help       # details for any subcommand
```

The ones you'll use most:

| Command | Purpose |
|---|---|
| `gate init` | Register the hook with your harness (see Quickstart) |
| `gate config` | Create and edit the YAML config |
| `gate scan` | PII risk report across your schema |
| `gate enable` / `gate disable` | Toggle redaction without uninstalling |
| `gate allowlist add/remove/list` | Manage column-name false positives |
| `gate validate` | Check config for errors before the first session |
| `gate protect` / `gate unprotect` *(Unix only)* | Transfer config ownership to root |
| `gate uninstall` | Remove everything gate added to your system |

See [docs/commands.md](docs/commands.md) for the full reference, including `gate run`, `gate mcp`, and the `--wrap-mcp` / `--scope` / `--harness` flags.

### Config file protection (Unix only)

For a stronger guarantee, transfer ownership of the config to root so the agent cannot modify it:

```bash
sudo gate protect      # any future enable/disable/config/allowlist now needs sudo
sudo gate unprotect    # restore direct write access
```

Enforced at the OS level across all harnesses (Claude Code, opencode, Copilot CLI). Not supported on Windows.

## Documentation

- [Configuration](docs/configuration.md) — full YAML schema and built-in PII detection rules
- [Commands](docs/commands.md) — full subcommand reference
- [MCP setup](docs/mcp.md) — wrapping existing MCP servers and registering new ones
- [Scan queries](docs/scan.md) — schema-query examples for each database
- [Config file locations](docs/config-locations.md) — where each harness stores hooks and MCP settings
- [Troubleshooting](docs/troubleshooting.md) — common issues and fixes

## Uninstallation

```bash
gate uninstall
brew uninstall gate
```

`gate uninstall` removes the hook from your harness settings, the config directory at `~/.config/gate/`, and any gate-generated opencode plugins. It shows what will be deleted and asks for confirmation.

## Contributing

Bug reports and pull requests are welcome. For significant changes, open an issue first to discuss the proposal. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, pre-commit checklist, and safety rules for redaction changes.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md).
