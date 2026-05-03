# Implementation Plan: redact

## Approach

Build the project bottom-up across four milestones: foundation (config + patterns) → Gate 2 (the load-bearing safety net) → Gate 1 + integration (`redact run`) → hook surface (`hook` + `init` + `config`). Each milestone ends in a runnable, testable state. The first three are useful even before the hook layer ships — `redact run` can be exercised manually for end-to-end testing without any harness integration.

This ordering puts the highest-risk component (Gate 2's correctness on real data) earliest and the harness-coupled components (which are the most fragile to test) last. If Gate 2 has problems, we want to know in week one, not week three.

**Before the milestones: build a prototype first.** See the Prototype section below.

---

## Prototype (before Milestone 1)

Goal: prove the end-to-end flow works inside Claude Code in a few hours, before investing in the full implementation.

**What to build:**

- `redact hook` — reads the Bash command from stdin; if `argv[0]` matches a hardcoded tool list (`tkpsql`, `tkdbr`, `mysql`, `psql`), rewrites to `redact run -- <original command>`; otherwise passes through unchanged.
- `redact run` — spawns the subprocess, captures stdout, runs Gate 2 with hardcoded PII patterns (email, SSN, phone, credit card via Luhn), prints redacted JSON to stdout.

**What to skip:**

- Gate 1 (SQL inspection) — Gate 2 alone proves the safety net
- `redact init` — manually insert the hook entry into `~/.claude/settings.json`
- `redact config`, `redact list`, `redact validate` — hardcode tool list and patterns
- Full config system, harness detection, atomic writes, error handling

**Hook entry to install manually:**

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "redact hook" }] }
    ]
  }
}
```

**Exit criterion:** inside a live Claude Code session, ask the AI to run a query tool that returns JSON with PII — observe the redacted output returned to the model. Gate 2 must catch email, SSN, and phone in a realistic JSON payload. Once this works, proceed to Milestone 1 and replace the prototype with the production implementation.

---

## Repository setup

**Step 1.** Create the Cargo workspace:

```
redact/
  Cargo.toml                 # workspace root
  crates/
    common/Cargo.toml        # config, patterns, redactor, error, harness
    gate1/Cargo.toml         # SQL tokenizer + column extractor
    redact/Cargo.toml        # main binary
```

**Step 2.** Pin dependencies in workspace `Cargo.toml`:

- `clap = { version = "4", features = ["derive"] }`
- `serde = { version = "1", features = ["derive"] }`
- `serde_json = { version = "1", features = ["preserve_order"] }`
- `serde_yaml = "0.9"`
- `regex = "1"`
- `shell-words = "1"`
- `anyhow = "1"`, `thiserror = "1"`
- `tempfile = "3"` (test-only)

**Step 3.** Set up CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`.

---

## Milestone 1 — Foundation (`common` crate)

Goal: config loads cleanly, patterns compile, errors render correctly. No CLI yet.

**Step 4. `common/error.rs`** — `ErrorResponse` struct (serializes to `{"error": "..."}`), `exit_with_error(msg)` helper that prints the JSON to stdout and exits 1.

**Step 5. `common/config.rs`** — Config types:

```rust
pub struct Config {
    pub tools: HashMap<String, ToolConfig>,
    pub pii: PiiConfig,
}
pub struct ToolConfig { pub sql_arg: Option<String> }
pub struct PiiConfig {
    pub column_names: Vec<String>,        // merged with built-in defaults
    pub action: Action,                    // Warn | Redact | Reject
    pub wildcard_policy: WildcardPolicy,   // Warn | Reject
    pub patterns: HashMap<String, Pattern>,
    pub column_name_boost: f32,            // default 0.15
    pub confidence_threshold: f32,         // default 0.8
    pub redaction: String,                 // default "[PII:{type}]"
    pub include_summary: bool,             // default true
}
pub struct Pattern { pub regex: String, pub confidence: f32 }
```

Implement `Config::load()` that resolves the path from `REDACT_CONFIG` → `~/.config/redact/config.yaml`, merges defaults with user values (so users only specify overrides), and returns a typed error for parse failures.

**Step 6. `common/patterns.rs`** — Built-in defaults baked in: column-name denylist (`email`, `ssn`, `dob`, `phone`, `npi`, `credit_card`, `card_number`, `cvv`, `passport`, `license_number`, `full_name`, `first_name`, `last_name`, `birthdate`), regex defaults with their base confidences, `column_name_boost = 0.15`, `confidence_threshold = 0.8`. `CompiledPatterns` struct holds compiled `Regex` + score + name. `Luhn::check(&str) -> bool` for credit cards.

**Step 7. `common/harness.rs`** — `is_agent_harness() -> bool` checks `CLAUDECODE`, `OPENCODE`, `COPILOT_CLI`, `COPILOT_RUN_APP`.

**Step 8. Tests** — Config: round-trip parse, defaults merge, missing file error, malformed YAML error. Patterns: each built-in regex matches its golden corpus and rejects negative cases. Luhn: valid/invalid card test vectors.

**Exit criterion:** `cargo test -p common` passes; manual `Config::load()` from a sample YAML returns the expected struct.

---

## Milestone 2 — Gate 2 (`common/redactor.rs`)

Goal: given a JSON payload + `RedactPlan`, return a redacted JSON payload + summary. This is the highest-risk component — wrong here means PII leaks.

**Step 9. `RedactPlan` struct** in `common/`:

```rust
pub struct RedactPlan {
    pub forced_columns: HashMap<String, String>,  // lowercased key → type label
    pub warnings: Vec<String>,
    pub rejected: bool,
}
impl RedactPlan { pub fn empty() -> Self { ... } }
```

**Step 10. Shape detection** — `detect_shape(&Value) -> Shape` enum (`Error | Object | Array | Other`). Error means top-level object with an `error` key.

**Step 11. Tree walk** — recursive function that visits every `(key, value)` pair. For string leaves, build a `Vec<Match>` with `(start, end, type, confidence)` from regex + Luhn + forced-column check. Pick the highest-confidence match per value. If `confidence >= threshold`, replace the value with the redaction template; otherwise add a low-confidence warning to the summary. Forced-column matches always win, score = 1.0, no regex run.

**Step 12. Summary attachment** — `apply_summary(payload, summary, include_summary, shape)`:

- `Error` → unchanged.
- `Object` → set `payload["_redact_summary"] = summary` if enabled.
- `Array` + enabled → wrap as `{"rows": payload, "_redact_summary": summary}`.
- `Array` + disabled → unchanged.
- `Other` → unchanged.

**Step 13. Use `serde_json` with `preserve_order`** so column order in output matches input (NFR-4).

**Step 14. Tests** — Golden-file tests with input/output JSON pairs covering: object with `rows`, bare array, error pass-through, nested JSONB, columns with PII keys but null values, multiple matches in one string (highest confidence wins), forced column from `RedactPlan` (regex doesn't run), low-confidence match (warned but not redacted), Luhn-passes (always redact regardless of column), Luhn-fails on a 16-digit non-card string. Property test: redaction is idempotent (running redact twice = running once).

**Exit criterion:** Hand-craft 8–10 sample query result files (mix of toolkit-shaped and `mysql --json`-shaped, with realistic PII), assert correct redaction. False-negative rate on the test corpus = 0.

---

## Milestone 3 — Gate 1 (`gate1` crate)

Goal: extract column names from a SQL string. Best-effort.

**Step 15. `gate1/tokenizer.rs`** — Hand-written SQL tokenizer that recognizes: identifiers, quoted identifiers (`"col"`, `` `col` ``), commas, parens, dots, whitespace, comments (`--`, `/* */`), keywords (`SELECT`, `FROM`, `AS`, `DISTINCT`). Returns `Vec<Token>`.

**Step 16. `gate1/lib.rs`** — `extract_columns(sql: &str) -> ColumnExtraction`:

```rust
pub enum ColumnExtraction {
    Wildcard,                                 // SELECT *
    Columns(Vec<ExtractedColumn>),            // explicit list
    Unknown,                                  // can't parse confidently
}
pub struct ExtractedColumn {
    pub output_name: String,    // alias if present, else stripped column
    pub original: String,       // pre-alias column name (used as type label)
}
```

Walk tokens between `SELECT` and `FROM`, splitting on commas at the top paren level. For each entry: detect `AS <alias>` or trailing identifier-as-alias; strip schema/table qualifiers (`u.email` → `email`); ignore function calls (`COUNT(*)` → not a column).

**Step 17. `gate1::build_plan(extraction, sql_action, wildcard_policy, denylist) -> RedactPlan`** — applies the action table from FR-3.

**Step 18. Tests** — Golden SQL strings: simple SELECT, aliases (`AS contact`, bare-identifier alias), qualified columns (`u.email`, `users.email`), `SELECT *`, `SELECT DISTINCT`, function calls (`LOWER(email)`), CTEs (best-effort — document as unsupported), subqueries in SELECT list (best-effort), comments inline. Each test pins the extracted column list.

**Exit criterion:** All golden cases pass. Document explicit limitations in a comment block at the top of `lib.rs`.

---

## Milestone 4 — `redact run` (the worker)

Goal: end-to-end pipeline — spawn subprocess, capture stdout, run both gates, emit JSON.

**Step 19. `redact/main.rs`** — `clap` derive setup with all subcommands: `Run`, `Hook`, `Init`, `Config`, `List`, `Validate`, `Version`. Dispatch to module handlers. Harness gating is a single `is_agent_harness()` check at the top of `Init` and interactive `Config` handlers.

**Step 20. `redact/run.rs`** — `run(args: Vec<String>)`:

1. Load config.
2. Inspect `args[0]` (basename) → look up `tools[name].sql_arg`.
3. If `sql_arg` is set, scan `args` for `--sql VALUE` or `--sql=VALUE` (or whatever the configured flag is). Run `gate1::build_plan(...)` with the extracted SQL → `RedactPlan`.
4. If `plan.rejected`, emit error JSON, exit 1.
5. Spawn subprocess with `args[0]` and `args[1..]`, inheriting parent env, capturing stdout. Wait.
6. If subprocess exit ≠ 0, forward stdout (it may already be an error JSON or arbitrary text) and propagate exit code.
7. Parse stdout as JSON. If parse fails, forward unchanged (the tool may have emitted non-JSON for a reason).
8. Run Gate 2 with the plan.
9. Print compact JSON to stdout, exit 0.

**Step 21. Subprocess plumbing** — use `std::process::Command`. Stream stderr through unchanged (do not buffer). Do not add a redact-side timeout in v1; the underlying tool has its own.

**Step 22. Tests** — Integration tests that wire `redact run` against a fake-tool binary (a tiny shell script that emits known JSON for known SQL), assert end-to-end behavior on: tkpsql-shape, mysql-shape, error pass-through, non-JSON output pass-through, non-zero exit code propagation.

**Exit criterion:** `redact run -- ./fake-tkpsql --sql "SELECT email FROM users"` produces the expected redacted JSON. `cargo test -p redact` integration tests pass.

---

## Milestone 5 — Hook surface (`hook` + `init` + `config` + `list` + `validate`)

Goal: the install flow and the harness-facing surface.

**Step 23. `redact/hook.rs`** — `hook()`:

1. Read full stdin (the Bash command line as a single string).
2. `shell_words::split` to get tokens. If parse fails, emit unchanged + exit 0.
3. Take basename of `tokens[0]` (strip leading paths).
4. Load config. If basename not in `tools:`, write input verbatim to stdout, exit 0.
5. If tokens start with `redact run`, write input verbatim (loop avoidance), exit 0.
6. Build rewrite: `redact run -- <original command>` (preserve quoting using `shell_words::join`). Write to stdout, exit 0.

**Step 24. Performance discipline** — config load on each hook invocation must be ≤ 5ms. Measure with `criterion` if needed; if too slow, add a parsed-config cache keyed on file mtime in `~/.cache/redact/config.bin`. Defer the cache unless benchmarks show the need.

**Step 25. `redact/init.rs`** — `init(harness: Harness)`:

1. Validate harness is `claude-code` (the only supported value in v1).
2. Resolve target path (`~/.claude/settings.json`).
3. Read existing JSON or create `{}`.
4. Idempotently insert into `hooks.PreToolUse` an entry: `{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "redact hook" }] }`. If an entry with this exact `command` already exists, skip; print "already installed". If a different `redact hook` variant exists, replace. Never duplicate.
5. Write atomically (write to tempfile, rename).
6. Print success + next-step hint: "Run `redact config` to define which tools to intercept."

**Step 26. `redact/config_cmd.rs`** — `config(args)`:

- `--path`: resolve and print the config path. Exit 0.
- `--print`: load the file and print its raw contents to stdout. Exit 0.
- `--init-only`: if file missing, write starter from `starter.rs` (creating parent dir, logging the creation). Exit 0.
- No flags (default): same as `--init-only` if missing; then resolve `$VISUAL` → `$EDITOR` → `vi`, spawn it with the config path, wait for editor to exit. Inherit terminal stdio.

**Step 27. `redact/starter.rs`** — embedded starter config string with comments and the four built-in tools (`tkpsql`, `tkdbr`, `mysql`, `psql`). All commented except `tkpsql`/`tkdbr` to give a sensible default for the toolkit-companion case.

**Step 28. `redact/list.rs`** — Load config, print `tools:` entries: name + `sql_arg` value, two columns. For each tool, append "(raw client — credentials reachable to AI)" if it's in the raw-client set; "(toolkit-managed)" if it's `tkpsql`/`tkdbr`.

**Step 29. `redact/validate.rs`** — Load config, compile every regex (catching errors), warn on:

- Raw clients in `tools:` (soft warning, exit 0).
- Custom regex with no `confidence` field (use default, warn).
- Any `confidence > 1.0` or `< 0.0` (error, exit 1).
- Pattern key collides with a built-in but has different semantics (info).

Exit 0 if all checks pass with at most warnings; exit 1 on errors.

**Step 30. Tests** — Hook: 12+ cases — passthrough, intercept, loop avoidance, malformed input, raw-client (`mysql ...`), command with quoting (`tkpsql --sql "SELECT 'a b'"`). Init: idempotency (run twice, assert no duplicate), upgrade (different command string gets replaced), file creation when missing. Config: starter creation, $EDITOR fallback chain (test by setting envs to `/usr/bin/true`).

**Exit criterion:** End-to-end smoke test: clean `~/.config`, run `redact init && redact config --init-only`, then simulate a Claude Code Bash hook call by piping a tkpsql command into `redact hook`, observe correct rewrite. Run the rewrite under a fake-tool shim, observe correct redaction.

---

## Milestone 6 — Polish & ship

**Step 31.** README with quickstart (3 commands: install, init, config).

**Step 32.** Error message audit: every user-facing error names the actionable next step.

**Step 33.** Performance check: NFR-1 says <100ms for 1000 rows × 50 cols. Benchmark with `criterion` against a synthetic payload; if blown, profile.

**Step 34.** Manual smoke test against actual `tkpsql` and `mysql --json`. The fake-tool tests are necessary but not sufficient — real tools have surprises (mysql's NULL representation, postgres array syntax, etc.).

**Step 35.** Tag v0.1.0.

---

## Milestone 7 — Close the non-JSON output gap

**Motivation:** Gate 2 currently requires JSON stdout. The shipped design relies on a per-tool `json_tool` config field (see `crates/redact/src/config.rs:22` and `crates/redact/src/hook.rs:57`): when the AI types `psql -c "..."`, the hook rewrites the spawn target to a side binary like `psql-json` and that wrapper is what produces JSON. The demo works because `psql-json` is installed on the demo host. The mechanism breaks silently when the wrapper is missing — inside a Docker container, on a fresh laptop, in CI — because (a) `psql`/`mysql` have no native `--json` output flag, (b) nothing pre-flights the wrapper's existence, and (c) on parse failure today's `redact run` forwards stdout unchanged. Net result: a silent PII leak whenever the wrapper isn't on PATH.

The right answer is to make `redact run` produce JSON itself by **rewriting the SQL** before spawning the subprocess, using the JSON-construction functions every modern relational DB ships with (`row_to_json` / `json_agg` in Postgres, `JSON_OBJECT` / `JSON_ARRAYAGG` in MySQL). When rewrite succeeds we keep full Gate 2 protection (column-aware, forced-column path applies). When rewrite is not safe — multi-statement input, `\` meta-commands, `COPY`, `EXPLAIN`, side-effecting queries — we fail closed instead of leaking. This makes `redact` self-contained: no side wrapper needs to exist, no PATH dependency in the container.

`json_tool` becomes deprecated by `rewrite_sql`. They solve the same problem; `rewrite_sql` does it without requiring an extra binary on PATH. We keep `json_tool` working for one release for backwards compatibility, then remove it.

This milestone has three parts: (A) fail closed on non-JSON output and pre-flight `json_tool` existence (the safety net), (B) SQL rewrite for raw clients (the primary path), (C) deprecate `json_tool` in favor of `rewrite_sql`.

### Part A — Fail closed on non-JSON + pre-flight `json_tool` (must-have, ships first)

**Step 36. `redact run` fails closed when stdout is not JSON.** Today: parse failure → forward unchanged. New behavior: parse failure → emit `{"error": "tool stdout was not JSON; refusing to forward unredacted output. Configure rewrite_sql for this tool, or install the json_tool wrapper."}` and exit 1. Update integration tests for the new failure mode.

**Step 37. `redact run` pre-flights `json_tool` before spawn.** When a tool's `json_tool` is configured, `redact run` resolves it on PATH (the same lookup the OS will do at exec time) before spawning. If not found, emit `{"error": "configured json_tool '<name>' not found on PATH; cannot redact output. Install the wrapper or configure rewrite_sql instead."}` and exit 1. Without this check the OS exec error bubbles up as a generic failure and the AI gets confused / retries the bare `psql` command; the explicit error is both safer and more debuggable. Add a unit test using a tempdir-controlled PATH.

**Step 38. `validate` warns on raw clients without rewrite or wrapper configured.** When a tool entry has a basename in the raw-client set (`psql`, `mysql`, `sqlite3`, `mongosh`, `mysqlsh`) and neither `rewrite_sql` (Step 39) nor an existing `json_tool` is configured, emit a hard warning naming the tool and pointing at the rewrite option. When `json_tool` *is* configured, `validate` also resolves it on PATH and warns if missing — same logic as the runtime pre-flight, surfaced earlier. Soft-warn-on-raw-client (existing FR) is upgraded from "credentials reachable" to also cover output-format risk.

**Exit criterion for Part A:** Three behaviors verified by tests: (i) a `psql -c "SELECT email FROM users"` invocation with no `json_tool` and no `rewrite_sql` returns the Step 36 error JSON; (ii) the same invocation with `json_tool: psql-json` and `psql-json` not on PATH returns the Step 37 error JSON; (iii) `redact validate` warns on both conditions. This part is independently shippable — Part B builds on top.

### Part B — SQL rewrite for raw clients (primary path)

**Step 39. Per-tool `rewrite_sql` config.** Add to `ToolConfig`:

```rust
pub enum RewriteDialect { Postgres, Mysql }
pub struct ToolConfig {
    pub sql_arg: Option<String>,
    pub json_tool: Option<String>,              // deprecated; see Part C
    pub rewrite_sql: Option<RewriteDialect>,    // None = no rewrite
    pub rewrite_extra_args: Vec<String>,         // e.g. ["-t", "-A"] for psql
}
```

When `rewrite_sql` is set, `redact run` rewrites the SQL string in the configured `sql_arg` and prepends `rewrite_extra_args` to the spawned argv. If both `rewrite_sql` and `json_tool` are set on the same entry, `rewrite_sql` wins and `validate` warns about the redundant `json_tool`.

**Step 40. `gate1::rewrite::wrap_select(sql, dialect, plan) -> RewriteResult`.** Returns one of:

```rust
pub enum RewriteResult {
    Rewritten(String),       // safe to send to the DB
    Skip(String),            // reason — fall through to fail-closed
}
```

Rewrite rules:

- **Postgres:** `<sql>` → `SELECT coalesce(json_agg(row_to_json(_r)), '[]'::json) FROM (<sql>) _r`. Combined with `psql -t -A`, output is a single line containing a JSON array.
- **MySQL:** `<sql>` → `SELECT JSON_ARRAYAGG(JSON_OBJECT(<key/val pairs from Gate 1's extracted columns>)) FROM (<sql>) _r`. Requires Gate 1 to have an explicit column list — `SELECT *` and `Unknown` extractions skip the rewrite. Combined with `mysql -N -B`.

Skip conditions (return `Skip` with reason):

- Multiple statements separated by `;` (after stripping trailing whitespace/comments).
- Leading `\` meta-command (psql).
- Top-level keyword is not `SELECT` / `WITH` (so `COPY`, `EXPLAIN`, `SHOW`, DML, DDL all skip).
- For MySQL: Gate 1 column extraction is `Wildcard` or `Unknown`.
- SQL already wraps in `json_agg` / `JSON_ARRAYAGG` (don't double-wrap — detect and pass through).

**Step 41. `redact run` dispatches on `rewrite_sql`.** New flow when `rewrite_sql` is set:

1. Load config, find tool entry, find SQL via `sql_arg`.
2. Run Gate 1 column extraction → `RedactPlan` (unchanged).
3. Call `wrap_select(sql, dialect, plan)`.
4. If `Rewritten(new_sql)`: substitute back into argv at the `sql_arg` position; prepend `rewrite_extra_args` to the rest of argv.
5. If `Skip(reason)`: append the reason to `plan.warnings` and proceed without rewrite. The fail-closed check from Step 36 catches the resulting non-JSON output.
6. Spawn subprocess, capture stdout.
7. Parse stdout. For Postgres: stdout is a JSON array (or `[]`); wrap as `{"rows": <array>}` for the existing shape pipeline. For MySQL: same — `JSON_ARRAYAGG` returns a JSON array.
8. Run Gate 2 with the plan as today.

**Step 42. Output unwrapping and shape consistency.** The rewritten output is always a JSON array. Reuse Milestone 2's array-shape handling: wrap as `{"rows": [...], "_redact_summary": ...}` when `include_summary: true`, otherwise return the bare array. The AI sees the same shape it would see from `tkpsql`, so prompt expectations stay consistent.

**Step 43. Error and edge-case handling.**

- **DB error from the rewritten query.** If the subprocess exits non-zero, forward stdout unchanged and propagate exit. Add a warning to `_redact_summary.warnings` only if we successfully attached a summary (i.e., output parsed); for non-zero-exit + non-JSON output, just propagate.
- **DB rewrites the column names** (Postgres lowercases unquoted identifiers in `row_to_json`; aliases survive). Gate 1 already lowercases keys for forced-column matching, so this aligns. Add an explicit test that `SELECT email AS Contact FROM users` produces a key `contact` after rewrite and that Gate 1's plan still matches.
- **Empty result set.** Postgres' `json_agg` returns `NULL` on empty input; the `coalesce(..., '[]'::json)` wrap above handles it.
- **Whitespace / trailing semicolon in user SQL.** Strip trailing `;` and surrounding whitespace before wrapping; otherwise the subquery is a syntax error.

**Step 44. Tests.**

- Unit: `wrap_select` golden cases — simple SELECT, SELECT with WHERE, JOIN, CTE (`WITH ... SELECT`), aliases, qualified columns, trailing semicolon, leading whitespace.
- Unit: `wrap_select` skip cases — multi-statement, `\d users`, `COPY ... TO STDOUT`, `EXPLAIN SELECT ...`, `INSERT`, `UPDATE`, already-wrapped query.
- Integration: fake `psql` shim that echoes the SQL it received and emits a synthetic JSON array. Assert the rewritten SQL contains `json_agg(row_to_json(_r))` and the args contain `-t -A`. Assert the redacted output preserves `rows` shape.
- Integration: same for MySQL with `JSON_ARRAYAGG` + `-N -B`.
- Integration: confirm Part A's fail-closed still triggers when rewrite is `Skip`-ped (e.g. `psql -c "\d users"` returns the error JSON, not aligned text).
- Negative: `rewrite_sql: None` (default for `tkpsql`/`tkdbr`) is unaffected.

**Exit criterion for Part B:** A `psql -c "SELECT email, ssn FROM users"` invocation through `redact run` (with `psql` configured per the new README recipe) returns the same shape as `tkpsql` would — `{"rows": [{"email": "[PII:email]", "ssn": "[PII:ssn]"}], "_redact_summary": {...}}` — using only stock `psql`, no shim binary required. `psql -c "\d users"` continues to fail closed via Part A. Same for `mysql -e`.

### Part C — Deprecate `json_tool` in favor of `rewrite_sql`

**Step 45. Mark `json_tool` deprecated in code.** Keep the field parsing and the hook rewrite path working unchanged — backwards compatibility for one release. On config load, if any tool has `json_tool` set, log a one-line deprecation notice on stderr (not stdout — must not pollute hook output): `redact: json_tool is deprecated, use rewrite_sql instead. See docs.` `validate` surfaces the same notice as a warning.

**Step 46. Migrate first-party config and docs.** Update `redact/starter.rs` to use `rewrite_sql` for the `psql`/`mysql` entries (no `json_tool`). Update `README.md` to remove the `json_tool: psql-json` example and replace it with the rewrite recipe. Update `docs/design.md` to describe both fields with `rewrite_sql` as the recommended path and `json_tool` as deprecated. Add a one-liner migration note: "If you previously configured `json_tool: psql-json`, replace with `rewrite_sql: postgres` and `rewrite_extra_args: [\"-t\", \"-A\"]` and uninstall the wrapper."

**Step 47. Plan removal.** Note in `docs/plan.md` (this milestone) that `json_tool` will be removed in v0.3.0 — but **do not remove it now**. Removing in the same release that introduces the deprecation breaks every existing user.

**Step 48. Docs.**

- `docs/design.md`: add a "SQL Rewrite" subsection under the Two-Gate Model. Document the rewrite templates per dialect, the skip conditions, and the trade-off (rewrite changes what the DB sees — error messages and `EXPLAIN` plans will reference the wrapped query). Update the Call Chain ASCII diagram to show the rewrite step between Gate 1 and subprocess spawn. Mark `json_tool` deprecated and link to the migration note.
- `README.md`: replace the "Raw clients" section's `json_tool` examples with:
  ```yaml
  tools:
    psql:
      sql_arg: "-c"
      rewrite_sql: postgres
      rewrite_extra_args: ["-t", "-A"]
    mysql:
      sql_arg: "-e"
      rewrite_sql: mysql
      rewrite_extra_args: ["-N", "-B"]
  ```
  Explain the trade-off in one paragraph: the DB sees a wrapped query; non-SELECT statements (`\d`, `COPY`, DML) are not rewritten and fail closed.
- `CLAUDE.md`: update Non-negotiables — failing closed on non-JSON output is a non-negotiable; `rewrite_sql` is the supported path for raw clients; `json_tool` remains for backwards compatibility but is deprecated.

**Exit criterion for Part C:** Existing configs using `json_tool` still work end-to-end (regression test); deprecation warning appears on stderr exactly once per `redact run` and on `redact validate`; starter config and README no longer mention `json_tool`; migration note is discoverable from both the README and `docs/design.md`.

### Risks specific to Milestone 7

1. **SQL the rewriter doesn't recognize as safe.** Rare dialect features, vendor extensions, query hints. Mitigation: when in doubt, `Skip` and let Part A fail closed — degraded UX but never a leak.
2. **Error messages reference the wrapped query.** A syntax error from the user's inner SQL surfaces with `... in subquery _r` context. Document this; it's a UX paper cut, not a correctness bug.
3. **`row_to_json` column lowercasing in Postgres.** Unquoted identifiers come back lowercase. Gate 1 already normalizes to lowercase, so forced-column matching works. Add a regression test pinning this contract.
4. **MySQL `JSON_OBJECT` requires explicit columns.** `SELECT *` cannot be rewritten without a schema lookup. Mitigation: skip; Part A fails closed; document in README that `SELECT *` against MySQL via raw `mysql` is unsupported (use `tkdbr` or list columns).
5. **Performance of rewriting on the DB side.** `json_agg` over a million rows builds a single big JSON value in DB memory. Mitigation: this is the same risk the AI would hit if it wrote the JSON wrapper itself — out of scope for redact to mitigate. Document.
6. **A query that already returns JSON gets double-wrapped.** Detect single-column SELECT whose expression starts with `json_`/`JSON_` and skip; add tests.
7. **Deprecation noise breaks the hook.** Logs to stdout would corrupt the rewritten command. Strict rule: deprecation goes to stderr only. Test pins this.

### Effort estimate

3–3.5 working days. Part A is ~one day (fail-closed branch + `json_tool` PATH pre-flight + validate updates + tests). Part B is ~1.5 days (`gate1::rewrite` module ~150 lines, dispatch wiring in `run.rs`, two dialect templates, ~20 unit tests, two integration shims). Part C is ~half a day (deprecation notice plumbing, starter/README/design migration, regression test).

---

## Critical files to write or carefully shape

| File | Why critical |
|---|---|
| `common/redactor.rs` | The load-bearing safety net. Bugs here = PII leaks. |
| `gate1/lib.rs` | Best-effort SQL parsing. Wrong here = false-negative on Gate 1, but Gate 2 catches it. Lower stakes than redactor but worth golden-test coverage. |
| `redact/hook.rs` | Runs on every Bash command — perf and correctness both matter. |
| `redact/init.rs` | Touches the user's harness settings JSON. Idempotency and atomic writes are mandatory. |
| `redact/run.rs` | Spawns subprocesses, handles their stdio. The integration glue — most cross-component bugs live here. |

---

## Risks and mitigations

1. **JSON parse failure on legitimate non-JSON output.** Some tools may emit a banner line before JSON. Mitigation: forward unparseable stdout unchanged; document this as known. If it bites real users, add a `json_starts_with: "{"` heuristic.

2. **`shell-words` parse mismatch with Bash.** `shell-words` doesn't perfectly emulate Bash (e.g., `$(...)` expansion). For the hook's simple matching purpose this is fine — we only need argv[0]. But document the limitation.

3. **Hook performance regression.** If config grows or someone adds 50 patterns, the hook gets slow. Mitigation: benchmark before shipping; add the mtime cache if needed.

4. **`tkpsql`/`tkdbr` output shape changing.** External dependency. Mitigation: shape detection (Milestone 2) is generic enough that adding a new shape is one match arm.

5. **Claude Code's hook contract changing.** External dependency. Mitigation: document the contract version in `init.rs` so we can detect drift.

---

## What we're explicitly not doing in v1

- ML-based PII classification
- Streaming / chunked output
- Multi-harness support (Cursor, Gemini CLI, etc.)
- Per-tool PII overrides
- Audit logging
- Schema lookup for `SELECT *` resolution
- Encrypted config
- IPv6 detection, non-Latin name detection

These are listed in requirements.md "Out of Scope" / Open Questions and are deferred behind v1.

---

## Effort estimate

5–7 working days for one engineer comfortable with Rust. Milestones 1–4 are roughly half the work (the core); Milestones 5–6 are the other half (UX surface, polish, real-world testing).
