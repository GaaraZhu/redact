use std::io::{self, Read, Write};

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

pub fn run(args: Vec<String>, verbose: bool) {
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => exit_with_error(&format!(
            "failed to load config: {e}. Run `gate config --init-only` to create a starter config."
        )),
    };

    // Stdin mode: no command args — read JSON from stdin and apply Gate 2 directly.
    if args.is_empty() {
        if !config.enabled || is_disabled_by_env() {
            io::copy(&mut io::stdin(), &mut io::stdout()).ok();
            return;
        }
        redact_stdin(verbose, &config);
        return;
    }

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
    let mut plan = build_gate1_plan(cmd_args, &basename, &config);

    if verbose {
        eprintln!("[gate] === Gate 1 ===");
        if plan.forced_columns.is_empty() {
            eprintln!("[gate] forced columns: none");
        } else {
            let mut cols: Vec<_> = plan.forced_columns.iter().collect();
            cols.sort_by_key(|(k, _)| k.as_str());
            for (col, pii_type) in cols {
                eprintln!("[gate] forced column: {} → {}", col, pii_type);
            }
        }
        if plan.warnings.is_empty() {
            eprintln!("[gate] warnings: none");
        } else {
            for w in &plan.warnings {
                eprintln!("[gate] warning: {}", w);
            }
        }
        eprintln!("[gate] === Gate 2: per-field decisions ===");
    }
    plan.verbose = verbose;

    if plan.rejected {
        exit_with_error(
            "query rejected: the query selects a denylisted PII column or uses SELECT *. \
             Rewrite the query to select only the columns you need, or set \
             `pii.wildcard_policy: warn` in your config to allow SELECT *.",
        );
    }

    // Resolve json_tool: if the tool has a wrapper, rewrite its token + sql_arg flag.
    let (spawn_binary, mut spawn_args) =
        resolve_spawn_command(cmd_args, tool_idx, &basename, &config);

    let tool_cfg = config.tools.get(&basename);

    if let Some(extra) = tool_cfg.map(|t| t.extra_args.as_slice()) {
        spawn_args.extend_from_slice(extra);
    }

    inject_curl_silent(&spawn_binary, &mut spawn_args);

    let pipe_cmd = tool_cfg.and_then(|t| t.pipe.as_deref());

    // Spawn subprocess; stderr passes through unchanged
    let output = if let Some(pipe) = pipe_cmd {
        let cmd_str = shell_words::join(
            std::iter::once(spawn_binary.as_str()).chain(spawn_args.iter().map(String::as_str)),
        );
        let full_cmd = format!("{cmd_str} | {pipe}");
        match std::process::Command::new("sh")
            .args(["-c", &full_cmd])
            .envs(env_pairs)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .output()
        {
            Ok(o) => o,
            Err(e) => exit_with_error(&format!("{basename}: {e}")),
        }
    } else {
        match std::process::Command::new(&spawn_binary)
            .args(&spawn_args)
            .envs(env_pairs)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .output()
        {
            Ok(o) => o,
            Err(e) => exit_with_error(&format!("{basename}: {e}")),
        }
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

/// Read JSON from stdin, apply Gate 2 redaction, and write to stdout.
/// Gate 1 is skipped (no SQL to parse); only pattern/column-name matching runs.
fn redact_stdin(verbose: bool, config: &Config) {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap_or_default();

    let plan = RedactPlan {
        verbose,
        ..RedactPlan::empty()
    };

    if verbose {
        eprintln!("[gate] === Gate 1 ===");
        eprintln!("[gate] stdin mode: no SQL, Gate 1 skipped");
        eprintln!("[gate] === Gate 2: per-field decisions ===");
    }

    let payload: serde_json::Value = match serde_json::from_str(input.trim()) {
        Ok(v) => v,
        Err(_) => {
            if verbose {
                eprintln!(
                    "[gate] input is not JSON — redaction skipped, passing through unchanged"
                );
            }
            print!("{input}");
            return;
        }
    };

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

/// Inject `-s` (silent) into curl invocations if not already present, suppressing
/// curl's progress meter which otherwise appears on stderr during piped output.
/// Handles direct `curl` calls and shell interpreter `-c` strings (e.g. `sh -c "curl ..."`).
fn inject_curl_silent(binary: &str, args: &mut Vec<String>) {
    let basename = command::token_basename(binary);
    if basename == "curl" {
        if !curl_has_silent_flag(args.iter().map(String::as_str)) {
            args.insert(0, "-s".to_string());
        }
        return;
    }
    if matches!(basename.as_str(), "sh" | "bash" | "zsh" | "dash") {
        let mut i = 0;
        while i < args.len() {
            if args[i] == "-c" {
                if let Some(shell_str) = args.get_mut(i + 1) {
                    *shell_str = rewrite_curl_in_shell_str(shell_str);
                }
                return;
            }
            i += 1;
        }
    }
}

/// Returns true if any arg token represents a curl silent flag (`-s`, `--silent`,
/// or a combined short flag containing `s` such as `-fsSL`).
fn curl_has_silent_flag<'a>(mut args: impl Iterator<Item = &'a str>) -> bool {
    args.any(|a| {
        a == "--silent" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('s'))
    })
}

/// Rewrite a shell command string by injecting `-s` after each `curl` invocation
/// that doesn't already have a silent flag.
fn rewrite_curl_in_shell_str(s: &str) -> String {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\bcurl\b([^|;&\n]*)").unwrap());
    re.replace_all(s, |caps: &regex::Captures| {
        let after = &caps[1];
        if curl_has_silent_flag(after.split_whitespace()) {
            caps[0].to_string()
        } else {
            format!("curl -s{after}")
        }
    })
    .into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|&x| x.to_string()).collect()
    }

    #[test]
    fn direct_curl_injects_s() {
        let mut args = s(&["http://localhost:8080/users"]);
        inject_curl_silent("curl", &mut args);
        assert_eq!(args, s(&["-s", "http://localhost:8080/users"]));
    }

    #[test]
    fn direct_curl_already_silent_no_change() {
        let mut args = s(&["-s", "http://localhost:8080/users"]);
        inject_curl_silent("curl", &mut args);
        assert_eq!(args, s(&["-s", "http://localhost:8080/users"]));
    }

    #[test]
    fn direct_curl_long_silent_no_change() {
        let mut args = s(&["--silent", "http://localhost:8080/users"]);
        inject_curl_silent("curl", &mut args);
        assert_eq!(args, s(&["--silent", "http://localhost:8080/users"]));
    }

    #[test]
    fn direct_curl_combined_flag_with_s_no_change() {
        let mut args = s(&["-fsSL", "http://localhost:8080/users"]);
        inject_curl_silent("curl", &mut args);
        assert_eq!(args, s(&["-fsSL", "http://localhost:8080/users"]));
    }

    #[test]
    fn shell_c_injects_s_into_curl() {
        let mut args = s(&["-c", "curl http://localhost:8080/users | jq -c ."]);
        inject_curl_silent("sh", &mut args);
        assert_eq!(args[1], "curl -s http://localhost:8080/users | jq -c .");
    }

    #[test]
    fn shell_c_curl_already_silent_no_change() {
        let mut args = s(&["-c", "curl -s http://localhost:8080/users | jq -c ."]);
        inject_curl_silent("bash", &mut args);
        assert_eq!(args[1], "curl -s http://localhost:8080/users | jq -c .");
    }

    #[test]
    fn shell_c_multiple_curls_both_injected() {
        let mut args = s(&["-c", "curl http://a/b && curl http://c/d"]);
        inject_curl_silent("sh", &mut args);
        assert_eq!(args[1], "curl -s http://a/b && curl -s http://c/d");
    }

    #[test]
    fn non_curl_binary_no_change() {
        let mut args = s(&["--query", "SELECT 1"]);
        inject_curl_silent("psql", &mut args);
        assert_eq!(args, s(&["--query", "SELECT 1"]));
    }
}
