use std::io::Write;

use crate::command;
use common::config::Config;
use common::error::exit_with_error;
use common::redactor::{redact, RedactPlan};
use gate1::{build_plan, extract_columns};

fn is_disabled_by_env() -> bool {
    std::env::var("GATE_DISABLED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

pub fn run(args: Vec<String>) {
    if args.is_empty() {
        exit_with_error("gate run: no command specified. Usage: gate run -- <tool> [args...]");
    }

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => exit_with_error(&format!(
            "failed to load config: {e}. Run `gate config --init-only` to create a starter config."
        )),
    };

    // When redaction is disabled (config or env var), act as a transparent passthrough.
    if !config.enabled || is_disabled_by_env() {
        passthrough(args);
        return;
    }

    // Split leading KEY=VALUE env-var assignments from the actual command.
    let env_count = args
        .iter()
        .take_while(|t| t.contains('=') && !t.starts_with('-'))
        .count();
    let (env_tokens, cmd_args) = args.split_at(env_count);

    if cmd_args.is_empty() {
        exit_with_error("gate run: no command after env vars. Usage: gate run -- <tool> [args...]");
    }

    let env_pairs: Vec<(&str, &str)> = env_tokens
        .iter()
        .filter_map(|kv| kv.split_once('='))
        .collect();

    // Find the configured tool in the command (may be preceded by wrapper binaries such as rtk).
    // Nested matches (tool inside sh -c "...") fall back to index 0 like the unknown-tool path,
    // since run.rs operates on the already-unwrapped outer command.
    let (tool_idx, basename) = match command::find_tool_token(cmd_args, &config) {
        Some(command::ToolMatch::Direct { idx, basename }) => (idx, basename),
        Some(command::ToolMatch::Nested { basename }) => (0, basename),
        None => (0, command::token_basename(&cmd_args[0])),
    };

    // Gate 1: build redact plan from SQL if tool has sql_arg configured
    let plan = build_gate1_plan(cmd_args, &basename, &config);

    if plan.rejected {
        exit_with_error(
            "query rejected: the query selects a denylisted PII column or uses SELECT *. \
             Rewrite the query to select only the columns you need, or set \
             `pii.wildcard_policy: warn` in your config to allow SELECT *.",
        );
    }

    // Resolve json_tool: if the tool has a wrapper, rewrite its token + sql_arg flag.
    let (spawn_binary, spawn_args) = resolve_spawn_command(cmd_args, tool_idx, &basename, &config);

    // Spawn subprocess; stderr passes through unchanged
    let output = match std::process::Command::new(&spawn_binary)
        .args(&spawn_args)
        .envs(env_pairs)
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

/// If `basename` has a `json_tool` configured, rewrite the tool token at `tool_idx` to the
/// wrapper binary and translate its `sql_arg` flag to `--sql`. All other args are preserved.
/// Returns `(binary, remaining_args)`.
fn resolve_spawn_command(
    cmd_args: &[String],
    tool_idx: usize,
    basename: &str,
    config: &Config,
) -> (String, Vec<String>) {
    let Some(tool_cfg) = config.tools.get(basename) else {
        return (cmd_args[0].clone(), cmd_args[1..].to_vec());
    };
    let (Some(json_tool), Some(sql_arg)) = (&tool_cfg.json_tool, &tool_cfg.sql_arg) else {
        return (cmd_args[0].clone(), cmd_args[1..].to_vec());
    };

    let eq_prefix = format!("{sql_arg}=");
    let new_args: Vec<String> = cmd_args
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == tool_idx {
                json_tool.clone()
            } else if t == sql_arg {
                "--sql".to_string()
            } else if let Some(val) = t.strip_prefix(&eq_prefix) {
                format!("--sql={val}")
            } else {
                t.clone()
            }
        })
        .collect();

    (new_args[0].clone(), new_args[1..].to_vec())
}

/// Spawn the command without any interception and forward stdout/stderr/exit code unchanged.
fn passthrough(args: Vec<String>) {
    // Strip leading KEY=VALUE env-var tokens.
    let env_count = args
        .iter()
        .take_while(|t| t.contains('=') && !t.starts_with('-'))
        .count();
    let (env_tokens, cmd_args) = args.split_at(env_count);
    if cmd_args.is_empty() {
        exit_with_error("gate run: no command after env vars. Usage: gate run -- <tool> [args...]");
    }
    let env_pairs: Vec<(&str, &str)> = env_tokens
        .iter()
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let status = match std::process::Command::new(&cmd_args[0])
        .args(&cmd_args[1..])
        .envs(env_pairs)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
    {
        Ok(s) => s,
        Err(e) => exit_with_error(&format!("{}: {e}", cmd_args[0])),
    };
    std::process::exit(status.code().unwrap_or(1));
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
