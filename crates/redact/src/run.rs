use std::io::Write;
use std::process::{Command, Stdio};
use serde_json::{json, Value};

use crate::redactor;

pub fn run(args: Vec<String>) {
    if args.is_empty() {
        println!("{}", json!({"error": "redact run: no command specified"}));
        std::process::exit(1);
    }

    let tool = &args[0];
    let tool_args = &args[1..];

    let output = match Command::new(tool)
        .args(tool_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            println!("{}", json!({"error": format!("{}: {}", tool, e)}));
            std::process::exit(1);
        }
    };

    // Non-zero exit: forward stdout unchanged and propagate exit code
    if !output.status.success() {
        std::io::stdout().write_all(&output.stdout).ok();
        std::process::exit(output.status.code().unwrap_or(1));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();

    // Non-JSON output: forward unchanged
    let payload: Value = match serde_json::from_str(stdout_str.trim()) {
        Ok(v) => v,
        Err(_) => {
            print!("{}", stdout_str);
            return;
        }
    };

    // Error JSON passthrough — never attach a summary to error responses
    if let Value::Object(ref map) = payload {
        if map.contains_key("error") {
            print!("{}", serde_json::to_string(&payload).unwrap_or(stdout_str));
            return;
        }
    }

    let result = redactor::redact(payload);
    let summary = json!({
        "redacted": result.redacted_count,
        "types": result.types,
        "warnings": result.warnings,
    });

    let out = match result.value {
        Value::Object(mut map) => {
            map.insert("_redact_summary".to_string(), summary);
            Value::Object(map)
        }
        Value::Array(arr) => json!({
            "rows": arr,
            "_redact_summary": summary,
        }),
        other => other,
    };

    println!("{}", serde_json::to_string(&out).unwrap());
}
