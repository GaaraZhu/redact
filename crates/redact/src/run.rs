use std::io::Write;

use common::config::Config;
use common::error::exit_with_error;
use common::redactor::{redact, RedactPlan};
use gate1::{build_plan, extract_columns};

pub fn run(args: Vec<String>) {
    if args.is_empty() {
        exit_with_error("redact run: no command specified. Usage: redact run -- <tool> [args...]");
    }

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => exit_with_error(&format!(
            "failed to load config: {e}. Run `redact config --init-only` to create a starter config."
        )),
    };

    let basename = std::path::Path::new(&args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(args[0].as_str())
        .to_string();

    // Gate 1: build redact plan from SQL if tool has sql_arg configured
    let plan = build_gate1_plan(&args, &basename, &config);

    if plan.rejected {
        exit_with_error(
            "query rejected: the query selects a denylisted PII column or uses SELECT *. \
             Rewrite the query to select only the columns you need, or set \
             `pii.wildcard_policy: warn` in your config to allow SELECT *.",
        );
    }

    // Spawn subprocess; stderr passes through unchanged
    let output = match std::process::Command::new(&args[0])
        .args(&args[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
    {
        Ok(o) => o,
        Err(e) => exit_with_error(&format!("{basename}: {e}")),
    };

    // Non-zero exit: forward stdout unchanged and propagate exit code
    if !output.status.success() {
        std::io::stdout().write_all(&output.stdout).ok();
        std::process::exit(output.status.code().unwrap_or(1));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();

    // Non-JSON output: forward unchanged (tool may emit a banner or plain text)
    let payload: serde_json::Value = match serde_json::from_str(stdout_str.trim()) {
        Ok(v) => v,
        Err(_) => {
            print!("{stdout_str}");
            return;
        }
    };

    // Gate 2
    let redacted = redact(payload, &plan, &config.pii);

    println!("{}", serde_json::to_string(&redacted).unwrap());
}

fn build_gate1_plan(args: &[String], basename: &str, config: &Config) -> RedactPlan {
    let sql_flag = match config
        .tools
        .get(basename)
        .and_then(|t| t.sql_arg.as_deref())
    {
        Some(f) => f,
        None => return RedactPlan::empty(),
    };

    let sql = match find_flag_value(args, sql_flag) {
        Some(s) => s,
        None => return RedactPlan::empty(),
    };

    let extraction = extract_columns(sql);
    build_plan(
        &extraction,
        &config.pii.action,
        &config.pii.wildcard_policy,
        &config.pii.effective_column_names(),
    )
}

/// Find the value of `flag` in `args`, supporting both `--flag VALUE` and `--flag=VALUE`.
fn find_flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let prefix = format!("{flag}=");
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).map(String::as_str);
        }
        if let Some(val) = arg.strip_prefix(&prefix) {
            return Some(val);
        }
    }
    None
}
