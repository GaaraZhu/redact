# redact

PII-filtering CLI that transparently intercepts AI agent query commands and redacts sensitive data before it reaches the model context. See `docs/` for full context.

## Docs

- `docs/requirements.md` — what to build and why
- `docs/design.md` — architecture, call chain, output format, design decisions
- `docs/plan.md` — milestone-by-milestone implementation plan with step numbers

## Current step

**Starting from the beginning — Step 1: create the Cargo workspace.**

Update this line when moving to the next step.

## Repository structure

```
redact/
  Cargo.toml            # workspace root
  crates/
    common/             # config, PII patterns, redactor (Gate 2), error types, harness detection
    gate1/              # SQL tokenizer + column extractor (Gate 1)
    redact/             # main binary (all subcommands)
```

## Build and test commands

```bash
cargo build
cargo test --all
cargo clippy -- -D warnings
cargo fmt --check
```

Run these after every step. Do not move to the next step until all pass.

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

Gate 1 uses a hand-written SQL tokenizer — do NOT add `sqlparser-rs`. See design.md for rationale.

## Non-negotiables

- **Gate 2 false negatives are worse than false positives.** When in doubt, redact. Default config errs toward redacting ambiguous matches.
- **Never write query results to disk.** All processing is in-memory.
- **No PII in logs or error messages.** `redact hook` and `redact run` must not log the AI's command line.
- **`init.rs` writes must be atomic.** Write to a tempfile, then rename. Never write directly to `~/.claude/settings.json`.
- **`redact init` and interactive `redact config` are blocked inside agent harnesses.** Check `is_agent_harness()` at the top of those handlers.
- **`redact hook` must be fast on the passthrough path** — single-digit ms. It fires on every Bash command.
- **Errors use `{"error": "..."}` format with exit code 1**, matching toolkit convention.

## Key invariants by file

| File | Why it matters |
|---|---|
| `common/redactor.rs` | The load-bearing safety net. Bugs here = PII leaks. Cover with golden-file tests before trusting it. |
| `gate1/lib.rs` | Best-effort SQL parsing. Wrong here = false-negative on Gate 1, but Gate 2 catches it. Document limitations at the top of the file. |
| `redact/hook.rs` | Runs on every Bash command — both perf and correctness matter. |
| `redact/init.rs` | Touches the user's harness settings JSON. Idempotency and atomic writes are mandatory. |
| `redact/run.rs` | Spawns subprocesses, handles their stdio. Most cross-component bugs live here. |

## Testing approach

- Write tests **before** or **alongside** each implementation step, not after.
- Each milestone has an exit criterion in `docs/plan.md` — do not advance until it passes.
- Milestone 2 (Gate 2 / `redactor.rs`) requires golden-file tests with realistic PII data. False-negative rate on the test corpus must be 0.
- Integration tests for `redact run` use a fake-tool binary (a shell script emitting known JSON for known SQL).
