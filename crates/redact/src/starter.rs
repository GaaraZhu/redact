pub const STARTER_CONFIG: &str = r#"# redact configuration

# Tools whose Bash invocations are intercepted and piped through `redact run`.
# Only tools listed here are intercepted; everything else passes through unchanged.
#
# json_tool: when set, the hook transparently rewrites invocations of the raw CLI
# (e.g. `psql -c "..."`) to the named JSON-output wrapper (e.g. `psql-json --sql "..."`),
# enabling Gate 2 PII redaction on the output. The wrapper must accept --sql <query>
# and emit JSON. Remove json_tool if you do not have a wrapper installed.
tools:
  tkpsql:
    sql_arg: "--sql"   # Gate 1 parses this SQL to extract column names for targeted redaction
  tkdbr:
    sql_arg: "--sql"
  psql:
    sql_arg: "-c"
    json_tool: "psql-json"
  mysql:
    sql_arg: "-e"
    json_tool: "mysql-json"
  sqlcmd:
    sql_arg: "-Q"
    json_tool: "sqlcmd-json"

pii:
  action: redact           # redact | warn | reject
  wildcard_policy: reject  # warn | reject

  # Add column names beyond the built-in denylist (email, ssn, dob, phone, npi, …)
  # column_names:
  #   - secret_token
  #   - api_key

  # Override or add PII regex patterns
  # patterns:
  #   internal_id:
  #     regex: '\bID-\d{6}\b'
  #     confidence: 0.9
"#;
