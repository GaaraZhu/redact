# Gate — Threat Model

This document describes what gate protects against, what it does not protect against, and the known
gaps in its detection. It is intended for security reviewers evaluating adoption and for users who
need to understand the limits of the tool.

---

## What gate is

Gate is a local proxy that sits between an AI agent and the data tools it calls. It intercepts
query results before they reach the model's context window and redacts PII it finds there.

It does **not** prevent the agent from making queries. It does **not** control what the agent is
allowed to ask. It only filters what the agent sees in the answer.

---

## Attacker model

Gate is designed against **an AI agent that inadvertently exfiltrates PII** — i.e. an agent that
queries a database, receives a result containing sensitive data, includes that data verbatim in its
context, and either logs it, summarises it, or sends it to an external API.

Gate is **not** designed against:

- A malicious agent that deliberately tries to bypass redaction (prompt-injection attacks that
  instruct the agent to disable gate, call tools in unusual ways, or exfiltrate data through
  side channels).
- A malicious human operator who controls the machine gate runs on.
- Network-level exfiltration of data the agent has already seen.

---

## The two-layer model

### Gate 1 — SQL intent analysis (best-effort)

Gate 1 parses the SQL argument passed to a configured tool and extracts the column names selected.
Any column that matches a PII heuristic is added to a `forced_columns` map that Gate 2 uses to
guarantee redaction regardless of value content.

Gate 1 is explicitly **best-effort**. Its known limitations are:

| Pattern | Behaviour | Safety net |
|---|---|---|
| `SELECT email, name FROM users` | Columns extracted and forced ✓ | — |
| `SELECT LOWER(email)` | Function call — column skipped | Gate 2 catches the value via email regex |
| `SELECT email AS contact` | Alias tracked as `contact → email` ✓ | — |
| `SELECT * FROM users` | Wildcard — all columns unknown | Gate 2 runs on every field; `wildcard_policy: reject` blocks the query entirely |
| CTEs (`WITH x AS (SELECT email ...)`) | Only the outermost SELECT is analysed | Gate 2 catches values via regex |
| Subqueries in SELECT list | Treated as opaque | Gate 2 catches values via regex |
| Non-standard SQL dialects | May produce an empty plan | Gate 2 catches values via regex |
| No `sql_arg` configured for the tool | Gate 1 is skipped entirely | Gate 2 runs on every field |

Gate 1 only runs when the tool is configured in `~/.config/gate/config.yaml` with a `sql_arg`
entry. For unconfigured tools, Gate 2 runs alone.

### Gate 2 — value and column-name redaction

Gate 2 runs on every query result. It applies three checks:

1. **Forced columns** (from Gate 1): always redacted regardless of value.
2. **Column-name heuristics**: the field key is tokenised and matched against a synonym table
   covering ~50 PII categories. Matches above a confidence threshold are redacted.
3. **Value patterns**: the field value is matched against built-in regex patterns and a Luhn check.

---

## What is and is not detected by value regex

Gate 2's built-in value patterns cover:

| Type | Detection method | Notes |
|---|---|---|
| Email address | Regex | High confidence. Standard RFC-5321 format. |
| US Social Security Number | Regex (`\d{3}-\d{2}-\d{4}`) | **Requires dashes.** `123456789` (no dashes) is not matched. |
| US phone number | Regex | US-centric format. Non-US numbers (e.g. `+64 21 ...`) may not match. |
| Payment card number | Regex + Luhn check | 13–16 digit strings that pass the Luhn algorithm. |

Everything else (IBAN, routing numbers, passport numbers, health data, biometric values, addresses,
NZ IRD, AU TFN, UK NHS numbers, Aadhaar, EU VAT) is **column-name-only**. If a column storing an
IBAN has an unusual name (e.g. `bank_ref`) and is not in the configured `column_names` list, Gate 2
will not redact its value.

Value patterns can be extended or overridden in config:

```yaml
pii:
  patterns:
    ird_number:
      regex: '\b\d{2}-\d{3}-\d{3}\b'
```

---

## Known bypasses

### Values that pass through Gate 2

- **SSN without dashes**: `123456789` is not matched by the SSN regex. Only `123-45-6789` is caught.
- **Non-US phone numbers**: formats like `+44 7911 123456` or `021 123 4567` may not be caught.
- **Encoded or transformed PII**: base64-encoded emails, URL-encoded values, or deliberately
  obfuscated strings (e.g. `a l i c e @ e x a m p l e . c o m`) are not detected.
- **Deliberate string literals in SQL**: `SELECT 'alice@example.com' AS note` — Gate 1 cannot
  extract this (not a column reference), but Gate 2 will still catch the value via email regex
  since the format is recognisable.
- **PII in non-JSON output**: if a tool returns plain text, CSV, or a non-JSON format, Gate 2
  cannot parse or redact it. The output is forwarded unchanged. Configure tools to emit JSON.

### Commands that bypass Gate 1 entirely

- Tools without a `sql_arg` entry in config receive no Gate 1 analysis. Gate 2 runs alone.
- When a tool is invoked via `SELECT * FROM ...` and `wildcard_policy` is `warn` (the default),
  Gate 2 runs but has no forced-column hints. Set `wildcard_policy: reject` if you want to block
  wildcard queries.

### Invocation patterns gate does not intercept

- **Python, JavaScript, or other non-Bash tool calls**: the hook fires only on the agent's Bash
  tool. Calls made through other harness tools (e.g. a custom Python function tool) are not
  intercepted.
- **Subprocesses spawned by the tool**: if `psql` internally forks another process to execute the
  query, gate sees only the final stdout. This is the normal case and is correctly handled.
  What is not handled is a tool that deliberately exfiltrates data via a subprocess whose output
  does not appear in the tool's stdout.
- **MCP resources and prompts**: the MCP proxy intercepts only `tools/call` responses.
  `resources/read`, `prompts/get`, and other MCP message types are forwarded without redaction.
  Most PII leakage paths go through `tools/call`, but this is a known gap.
- **`gate run` stdin mode**: when invoked with no arguments (`gate run` alone), Gate 1 is skipped
  and Gate 2 runs on the piped JSON with no SQL context.

### Error-shaped responses

JSON responses of the form `{"error": "..."}` are passed through unchanged. This is intentional —
error messages are diagnostic output, not query results. However, if a tool includes PII in an
error message (e.g. `{"error": "user alice@example.com not found"}`), that value will reach the
model.

### Disable mechanisms

Gate can be disabled by:

- Setting `GATE_DISABLED=1` in the environment. Any process that can set this env var before the
  tool runs can bypass gate entirely.
- Setting `enabled: false` in `~/.config/gate/config.yaml`. Access to this file is equivalent to
  disabling gate.
- Deleting or corrupting the config file. On config load failure, the hook silently passes through
  (fail-open) to avoid blocking every Bash command. `gate run` exits with an error instead.

These mechanisms exist for legitimate use (testing, debugging) but mean gate's security guarantee
is tied to the integrity of the local machine and the agent's environment.

---

## What gate does not protect

- **PII already in the model's context** from prior turns, system prompts, or file reads.
- **Agent memory or summarisation**: if the agent summarised PII it saw before gate was installed,
  that summary persists.
- **Direct file access**: the agent's file-reading tools are not intercepted.
- **Network requests made by tools**: if a tool sends data to an external service directly, gate
  never sees it.
- **The agent's own outputs**: gate only filters what goes *into* the model. What the model
  generates and sends to the user is outside gate's scope.
- **Inference from redacted data**: a sufficiently capable model may be able to infer original
  values from context even when specific fields are redacted.

---

## Configuration trust boundary

Gate reads its config from `~/.config/gate/config.yaml` (or the path in `GATE_CONFIG`). This file
controls which tools are intercepted, which patterns are active, and whether redaction is enabled
at all. The config file must be writable only by the user running the agent.

`gate init` writes to `~/.claude/settings.json` (Claude Code) or equivalent harness config. These
writes are atomic (tempfile-rename) and idempotent. `gate init` is blocked when running inside an
agent harness to prevent the agent from modifying its own hook configuration.

---

## Recommended configuration for stricter enforcement

```yaml
pii:
  wildcard_policy: reject    # block SELECT * instead of warning
  action: redact             # default; set to warn to audit without blocking

# Add patterns for PII types relevant to your region:
  patterns:
    ird_number:
      regex: '\b\d{2}-\d{3}-\d{3}\b'
    au_tfn:
      regex: '\b\d{3}\s\d{3}\s\d{3}\b'

# Add column names that are non-obvious in your schema:
  column_names:
    - contact_ref
    - cust_id
    - internal_note
```

Set `wildcard_policy: reject` if your agent should never issue `SELECT *`. This is the single
highest-leverage configuration change for reducing false-negative risk.
