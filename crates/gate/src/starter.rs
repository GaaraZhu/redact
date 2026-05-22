pub const STARTER_CONFIG: &str = r#"# gate configuration

# Set to false to disable all PII redaction.
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
  databricks:
    sql_arg: "--json"  # Databricks CLI sends SQL in a JSON payload
    json_sql_path: "statement"  # Extract SQL from the "statement" field in the JSON
  curl:
    pipe: "jq -c ."   # wraps curl output through jq so Gate 2 always receives JSON
  # Raw database clients (psql, mysql, mariadb) are supported but not enabled by
  # default — they typically require credentials on the command line, which leak
  # into the agent's context. See docs/configuration.md for opt-in examples and
  # safer alternatives (toolkit, MCP).

pii:
  action: redact           # redact | warn | reject
  wildcard_policy: warn    # warn | reject

  # False-negative fix: columns Gate missed that should be redacted.
  # Use when a column name isn't in the built-in synonym table.
  # column_denylist:
  #   - identification_number
  #   - secret_token

  # False-positive fix: columns Gate redacts that shouldn't be.
  # Name-based checks are skipped; value-level scanning (Luhn, regex) still applies.
  # column_allowlist:
  #   - employee_id   # internal auto-increment PK, safe to expose
  #   - city          # not sensitive in this schema

  # Override or add PII regex patterns
  # patterns:
  #   internal_id:
  #     regex: '\bID-\d{6}\b'
  #     confidence: 0.9

  # Append a deterministic 8-char hex suffix to each redacted placeholder so the
  # AI can correlate the same value across rows without seeing the raw data.
  # Example output: [PII:email:7f83b165]
  hash_values: false
  hash_salt: ""     # set a fixed secret for consistent hashes across runs
"#;
