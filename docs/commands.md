# Commands

Full reference for every `gate` subcommand. Use `gate --help` and `gate <subcommand> --help` for the same information from the CLI.

| Command | Purpose |
|---|---|
| `gate init [--harness claude-code\|opencode\|cursor\|copilot-cli\|codex] [--scope global\|project]` | Register the hook in the agent harness. `claude-code` (default) writes `~/.claude/settings.json`; `opencode` writes a TypeScript plugin at the chosen scope; `cursor` writes `~/.cursor/hooks.json` (or `.cursor/hooks.json` for project scope); `copilot-cli` writes `.github/hooks/PreToolUse.json` in the current repo root; `codex` writes `~/.codex/hooks.json` (or `.codex/hooks.json` for project scope). |
| `gate init --wrap-mcp [--servers a,b] [--yes]` | Convert existing MCP servers to `gate mcp` proxies. Dry-run by default; `--yes` to apply. `--servers` limits to a comma-separated list; omit to wrap all. Already-proxied servers are skipped. Respects `--harness` and `--scope`. |
| `gate init --mcp <name> --mcp-cmd <cmd>` | Register a single `gate mcp` proxy. For `claude-code`: `--scope global` (default) writes to `~/.claude.json`; `--scope project` writes to `./.mcp.json`. |
| `gate config [--path] [--print] [--init-only]` | Create and edit the config file. `--path` prints the resolved config path and exits. `--print` prints the raw config contents and exits. `--init-only` creates `~/.config/gate/config.yaml` without opening the editor — useful in scripts. |
| `gate scan [--verbose] [--json] [--review]` | Pipe schema query output (`SELECT TABLE_NAME, COLUMN_NAME ...`) into this to get a PII risk report across all tables. `--verbose` shows all detected columns without truncation. `--json` emits machine-readable JSON. `--review` enters an interactive triage session after the report to mark false-positive columns and add them to the allowlist. Exits 1 if any PII columns are found — scriptable in CI audits. |
| `gate allowlist add <col> [col...]` | Add column names to the allowlist. Allowlisted columns skip name-based redaction; value-based checks (Luhn, regex) still apply. Changes are written atomically to config. Duplicates are ignored. |
| `gate allowlist remove <col> [col...]` | Remove column names from the allowlist. |
| `gate allowlist list` | Show the current allowlist. |
| `gate retro` | Protection retrospective (a.k.a. stats / audit / report). Prints how many queries gate protected and how many PII fields it redacted, with a top-types breakdown. Reads from the on-disk stats log; disable collection with `stats.enabled: false` in config. |
| `gate enable` | Enable PII redaction (sets `enabled: true` in config). |
| `gate disable` | Disable PII redaction (sets `enabled: false` in config). |
| `gate validate` | Check config for errors and warnings. |
| `gate list` | Show configured tools and their SQL flags. |
| `gate run [--verbose] [-- <cmd>]` | Run a command through the redaction pipeline, or pipe JSON from stdin for direct Gate 2 inspection. Normally invoked by the hook; run manually to test. `--verbose` prints each field's Gate 2 decision to stderr. |
| `gate hook` | *(internal)* Hook entry point — invoked by the harness, not directly. |
| `gate mcp [--] <upstream-cmd> [args...]` | Run a stdio MCP proxy in front of `<upstream-cmd>`. Intercepts `tools/call` responses and redacts PII before they reach the model. Usually invoked by the harness, not directly. |
| `gate protect` *(Unix only)* | Transfer config ownership to root so agents cannot modify it. Run as: `sudo gate protect`. |
| `gate unprotect` *(Unix only)* | Restore your ownership of the config. Run as: `sudo gate unprotect`. |
| `gate uninstall` | Remove the hook, config directory, and gate-generated opencode plugins (with confirmation). |
| `gate version` | Print version. |
