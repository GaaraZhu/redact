# Troubleshooting

**Commands are passing through unredacted.**

Run `gate validate` to check for config errors. Confirm the hook is registered by checking that `~/.claude/settings.json` contains a `gate hook` entry — if not, re-run `gate init`. Then restart your agent session so the harness picks up the updated settings.

**`gate: command not found` inside the agent session.**

The shell PATH inside the harness may differ from your login shell. Find the full path with `which gate` in a normal terminal, then set `GATE_BIN` to that path or add the directory to the harness's PATH in your shell profile.

**OpenCode isn't intercepting commands after `gate init`.**

The plugin is loaded at session start — restart your opencode session after running `gate init --harness opencode`.

**Codex CLI isn't intercepting commands after `gate init`.**

Codex requires a few extra steps after `gate init --harness codex`: restart the session, open the Trust & Permissions UI, find the gate hook entry, mark it as trusted, and enable it. The hook will not fire until all three actions are completed.

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
