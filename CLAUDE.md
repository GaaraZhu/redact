# gate

PII-filtering CLI that transparently intercepts AI agent query commands and redacts sensitive data before it reaches the model context.

## Status

Milestone 9 (GitHub Copilot CLI) is deferred pending transparent-rewrite support in the Copilot hook.

## Notes
`crates/gate/src/run.rs` is the production Gate 1 + Gate 2 pipeline. Loads config,
runs gate1::extract_columns + gate1::build_plan on the SQL arg, spawns the subprocess,
pipes stdout through common::redactor::redact. All subcommands fully implemented.

## Repository structure

```
gate/
  Cargo.toml            # workspace root
  crates/
    common/             # config, PII patterns, redactor (Gate 2), error types, harness detection
    gate1/              # SQL tokenizer + column extractor (Gate 1)
    gate/               # main binary (all subcommands)
```

## Build and test commands

```bash
cargo build
cargo test --all
cargo clippy -- -D warnings
cargo fmt --check
```

Run these after every step. Do not move to the next step until all pass.

## Before every commit

Run all checks from the workspace root and fix any failures before committing:

```bash
cargo fmt --all
cargo clippy -- -D warnings
cargo test --all
```

Never commit if any of these fail.

## Dependencies (pin these in workspace Cargo.toml)

```toml
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["preserve_order"] }
serde_yaml = "0.9"
regex = "1"
shell-words = "1"
anyhow = "1"
thiserror = "1"
tempfile = "3"   # test-only
```

Gate 1 uses a hand-written SQL tokenizer — do NOT add `sqlparser-rs`.

## Safety pass (required after every implementation step)

Run this checklist before marking any step complete:

1. **False-negative scan** — review the new/changed redaction logic and identify any PII patterns that could slip through (e.g. value types not covered by regex, Luhn bypass, forced-column path skipped).
2. **Test coverage** — for each identified gap, add a test that would catch it. The test must fail before the fix and pass after.
3. **Non-negotiables audit** — verify every item in the Non-negotiables section below is still upheld by the current code.
4. **Exit criteria check** — verify milestone exit criteria are fully satisfied.

Do not advance the "Current step" in this file until all four items are checked.

## Non-negotiables

- **Gate 2 false negatives are worse than false positives.** When in doubt, redact. Default config errs toward redacting ambiguous matches.
- **Never write query results to disk.** All processing is in-memory.
- **No PII in logs or error messages.** `gate hook` and `gate run` must not log the AI's command line.
- **`init.rs` writes must be atomic.** Write to a tempfile, then rename. Never write directly to `~/.claude/settings.json`.
- **`gate init` and interactive `gate config` are blocked inside agent harnesses.** Check `is_agent_harness()` at the top of those handlers.
- **`gate hook` must be fast on the passthrough path** — single-digit ms. It fires on every Bash command.
- **Errors use `{"error": "..."}` format with exit code 1**, matching toolkit convention.
- **Hook output format must match the detected input format.** Today only the snake_case Claude Code shape is implemented (`hookSpecificOutput.updatedInput`). When opencode lands, the snake_case shape is reused — the opencode plugin formats its payload as snake_case before piping to `gate hook`, so the Rust side stays single-format. Copilot CLI support is deferred.

## Key invariants by file

| File | Why it matters |
|---|---|
| `common/redactor.rs` | The load-bearing safety net. Bugs here = PII leaks. Cover with golden-file tests before trusting it. |
| `gate1/lib.rs` | Best-effort SQL parsing. Wrong here = false-negative on Gate 1, but Gate 2 catches it. Document limitations at the top of the file. |
| `gate/hook.rs` | Runs on every Bash command — both perf and correctness matter. |
| `gate/init.rs` | Touches the user's harness settings JSON. Idempotency and atomic writes are mandatory. |
| `gate/run.rs` | Spawns subprocesses, handles their stdio. Most cross-component bugs live here. |

## Testing approach

- Write tests **before** or **alongside** each implementation step, not after.
- Each milestone has exit criteria — do not advance until all tests pass.
- Milestone 2 (Gate 2 / `redactor.rs`) requires golden-file tests with realistic PII data. False-negative rate on the test corpus must be 0.
- Integration tests for `gate run` use a fake-tool binary (a shell script emitting known JSON for known SQL).
