# Configuration

Config lives at `~/.config/gate/config.yaml` (override with `GATE_CONFIG`).

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

Add your own columns or patterns in the config schema below.

## Config schema

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

# MCP proxy settings (gate mcp)
mcp:
  # Set to false to forward all MCP tool results without redaction (debug mode).
  redact_tool_results: true
  # Payloads larger than this (bytes) are forwarded unredacted with a stderr warning.
  # Prevents OOM on very large file-content reads from MCP servers.
  max_payload_bytes: 5242880  # 5 MiB
```

## Raw database clients (opt-in)

`psql`, `mysql`, and `mariadb` are supported but **not in the default config**. They typically require credentials on the command line — `mysql -u user -pPASS ...`, `psql "postgresql://user:pass@host/db"` — and gate **does not redact the command itself**, only its output. Credentials in the command land in the agent's transcript, shell history, and process listing.

Prefer one of these instead:

- **Toolkit wrappers** (`tkpsql`, `tkmsql`, `tkdbr`) — inject credentials from a secrets store; the AI never sees a password.
- **MCP servers** — wrap the database behind an MCP server and use `gate init --mcp` or `gate init --wrap-mcp`. The AI calls a tool by name with no connection string involved.

If you still want to wire up a raw client (local dev, CI, or an environment where credentials are sourced from `~/.my.cnf` / `~/.pgpass` / IAM tokens rather than the command line), copy the relevant block into your `tools:` section:

```yaml
tools:
  psql:
    sql_arg: "-c"
    extra_args: ["--csv"]   # injected automatically; switches psql to CSV output for the pipe
    pipe: "python3 -c \"import sys,csv,json; r=csv.DictReader(sys.stdin); print(json.dumps(list(r)))\""
  mysql:
    sql_arg: "-e"
    extra_args: ["--batch"]   # injected automatically; switches mysql to TSV output for the pipe
    pipe: "python3 -c \"import sys,csv,json; r=csv.DictReader(sys.stdin,delimiter='\\t'); print(json.dumps(list(r)))\""
  mariadb:
    sql_arg: "-e"
    extra_args: ["--batch"]
    pipe: "python3 -c \"import sys,csv,json; r=csv.DictReader(sys.stdin,delimiter='\\t'); print(json.dumps(list(r)))\""
```

The `pipe` directive requires a Unix shell and `python3`. Not supported on Windows — use a JSON-native client (e.g. `mysqlsh --result-format=json`) without a pipe instead.
