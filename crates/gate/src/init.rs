use common::error::exit_with_error;
use common::harness::is_agent_harness;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const HOOK_COMMAND: &str = "gate hook";

pub fn run(
    harness: &str,
    scope: &str,
    mcp: Option<&str>,
    mcp_cmd: Option<&str>,
    wrap_mcp: bool,
    servers: Option<&str>,
    yes: bool,
) {
    if is_agent_harness() {
        exit_with_error(
            "gate init is not available inside an agent harness. \
             Run `gate init` in a terminal session outside the agent.",
        );
    }

    if mcp.is_some() && wrap_mcp {
        exit_with_error("--mcp and --wrap-mcp cannot be used together");
    }

    if servers.is_some() && !wrap_mcp {
        exit_with_error("--servers requires --wrap-mcp");
    }

    let filter = parse_servers_filter(servers);

    if wrap_mcp {
        match harness {
            "claude-code" => {
                let path = match claude_code_mcp_path(scope) {
                    Ok(p) => p,
                    Err(e) => exit_with_error(&e),
                };
                wrap_mcp_claude(&path, filter.as_deref(), yes);
            }
            "opencode" => {
                let path = match opencode_config_path(scope) {
                    Ok(p) => p,
                    Err(e) => exit_with_error(&format!("cannot resolve settings path: {e}")),
                };
                wrap_mcp_opencode(&path, filter.as_deref(), yes);
            }
            _ => exit_with_error(&format!(
                "--wrap-mcp is only supported for claude-code and opencode harnesses \
                 (got '{harness}')"
            )),
        }
        return;
    }

    if let Some(server_name) = mcp {
        let cmd_str = mcp_cmd.unwrap_or_else(|| {
            exit_with_error(
                "--mcp-cmd is required when --mcp is set. \
                Example: gate init --mcp postgres --mcp-cmd \"uvx mcp-server-postgres\"",
            )
        });
        match harness {
            "claude-code" => {
                let path = match claude_code_mcp_path(scope) {
                    Ok(p) => p,
                    Err(e) => exit_with_error(&e),
                };
                register_mcp_server(&path, server_name, cmd_str);
            }
            "opencode" => {
                let path = match opencode_config_path(scope) {
                    Ok(p) => p,
                    Err(e) => exit_with_error(&format!("cannot resolve settings path: {e}")),
                };
                register_mcp_server_opencode(&path, server_name, cmd_str);
            }
            _ => exit_with_error(&format!(
                "MCP registration is only supported for claude-code and opencode harnesses \
                 (got '{harness}')"
            )),
        }
        return;
    }

    match harness {
        "claude-code" => {
            let path = match claude_settings_path() {
                Ok(p) => p,
                Err(e) => exit_with_error(&format!("cannot resolve settings path: {e}")),
            };
            run_with_path(&path);
        }
        "opencode" => crate::init_opencode::run(scope),
        _ => exit_with_error(&format!(
            "unsupported harness '{harness}'; supported: claude-code, opencode. \
             Usage: gate init --harness <harness>"
        )),
    }
}

fn run_with_path(path: &Path) {
    let settings = read_settings(path);
    match insert_hook(settings) {
        HookInsertResult::AlreadyInstalled => {
            println!("gate hook is already installed in {}", path.display());
        }
        HookInsertResult::Done(updated) => {
            write_atomic(path, &updated).unwrap_or_else(|e| {
                exit_with_error(&format!("failed to write {}: {e}", path.display()))
            });
            println!("gate hook installed in {}", path.display());
            println!("Run `gate config` to define which tools to intercept.");
        }
    }
}

enum HookInsertResult {
    AlreadyInstalled,
    Done(Value),
}

fn read_settings(path: &Path) -> Value {
    if !path.exists() {
        return json!({});
    }
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to read {}: {e}", path.display())));
    serde_json::from_str(&contents)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to parse {}: {e}", path.display())))
}

fn new_hook_entry() -> Value {
    json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": HOOK_COMMAND }]
    })
}

fn insert_hook(mut settings: Value) -> HookInsertResult {
    normalize_settings(&mut settings);

    // Check for exact match (already installed)
    let already = {
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        has_exact_hook(arr)
    };
    if already {
        return HookInsertResult::AlreadyInstalled;
    }

    // Remove any gate hook variants, then append the canonical entry
    {
        let arr = settings["hooks"]["PreToolUse"].as_array_mut().unwrap();
        arr.retain(|entry| !entry_has_gate_hook(entry));
        arr.push(new_hook_entry());
    }

    HookInsertResult::Done(settings)
}

/// Ensure `settings` is `{"hooks": {"PreToolUse": [...]}}` (creating missing layers).
fn normalize_settings(settings: &mut Value) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().unwrap();

    let hooks = obj.entry("hooks".to_string()).or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }

    let pretu = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse".to_string())
        .or_insert_with(|| json!([]));
    if !pretu.is_array() {
        *pretu = json!([]);
    }
}

fn has_exact_hook(arr: &[Value]) -> bool {
    arr.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks
                    .iter()
                    .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(HOOK_COMMAND))
            })
            .unwrap_or(false)
    })
}

pub(crate) fn entry_has_gate_hook(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(is_gate_hook_variant)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Matches `gate hook` and variants like `/usr/local/bin/gate hook`.
fn is_gate_hook_variant(cmd: &str) -> bool {
    let mut parts = cmd.splitn(2, ' ');
    let prog = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim_start();
    let basename = Path::new(prog)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(prog);
    basename == "gate" && rest.starts_with("hook")
}

fn write_atomic(path: &Path, value: &Value) -> anyhow::Result<()> {
    let json_str = serde_json::to_string_pretty(value)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("settings path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("settings path has no filename"))?;
    let tmp_path = parent.join(format!("{file_name}.gate_tmp"));
    std::fs::write(&tmp_path, &json_str)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn register_mcp_server(path: &Path, server_name: &str, cmd_str: &str) {
    let upstream_parts = match shell_words::split(cmd_str) {
        Ok(parts) if !parts.is_empty() => parts,
        Ok(_) => exit_with_error("--mcp-cmd must not be empty"),
        Err(e) => exit_with_error(&format!("invalid --mcp-cmd: {e}")),
    };

    // gate mcp -- <upstream parts...>
    let mut args: Vec<Value> = vec![json!("mcp"), json!("--")];
    args.extend(upstream_parts.iter().map(|s| json!(s)));

    let server_entry = json!({
        "command": "gate",
        "args": args,
        "env": {}
    });

    let mut settings = read_settings(path);
    normalize_mcp_servers(&mut settings);
    settings["mcpServers"][server_name] = server_entry;

    write_atomic(path, &settings)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to write {}: {e}", path.display())));
    println!(
        "MCP server '{}' registered in {} (command: gate mcp -- {})",
        server_name,
        path.display(),
        upstream_parts.join(" ")
    );
    println!("Run `gate mcp -- {cmd_str}` to test the proxy manually.");
}

fn normalize_mcp_servers(settings: &mut Value) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().unwrap();
    let entry = obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
}

fn claude_settings_path() -> Result<PathBuf, String> {
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".claude/settings.json"))
}

/// Resolve the Claude Code MCP config path for the given scope.
/// "project" → ./.mcp.json; anything else ("user", "global") → ~/.claude.json.
fn claude_code_mcp_path(scope: &str) -> Result<PathBuf, String> {
    if scope == "project" {
        return Ok(PathBuf::from(".mcp.json"));
    }
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".claude.json"))
}

/// Resolve the opencode config path for the given scope.
/// "project" → ./opencode.json; anything else ("user", "global") → ~/.config/opencode/opencode.json.
fn opencode_config_path(scope: &str) -> Result<PathBuf, String> {
    if scope == "project" {
        return Ok(PathBuf::from("opencode.json"));
    }
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".config/opencode/opencode.json"))
}

fn register_mcp_server_opencode(path: &Path, server_name: &str, cmd_str: &str) {
    let upstream_parts = match shell_words::split(cmd_str) {
        Ok(parts) if !parts.is_empty() => parts,
        Ok(_) => exit_with_error("--mcp-cmd must not be empty"),
        Err(e) => exit_with_error(&format!("invalid --mcp-cmd: {e}")),
    };

    let mut command: Vec<Value> = vec![json!("gate"), json!("mcp"), json!("--")];
    command.extend(upstream_parts.iter().map(|s| json!(s)));

    let server_entry = json!({
        "type": "local",
        "command": command,
    });

    let mut config = if path.exists() {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => exit_with_error(&format!("failed to read {}: {e}", path.display())),
        };
        match serde_json::from_str::<Value>(&content) {
            Ok(v) => v,
            Err(e) => exit_with_error(&format!("failed to parse {}: {e}", path.display())),
        }
    } else {
        json!({})
    };

    if !config.get("mcp").is_some_and(|v| v.is_object()) {
        config["mcp"] = json!({});
    }
    config["mcp"][server_name] = server_entry;

    write_atomic(path, &config)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to write {}: {e}", path.display())));
    println!(
        "MCP server '{}' registered in {} (command: gate mcp -- {})",
        server_name,
        path.display(),
        upstream_parts.join(" ")
    );
    println!("Run `gate mcp -- {cmd_str}` to test the proxy manually.");
}

/// Parse a comma-separated `--servers` value into a sorted, deduplicated list.
/// Returns `None` if `raw` is `None` (meaning "wrap all").
fn parse_servers_filter(raw: Option<&str>) -> Option<Vec<String>> {
    raw.map(|s| {
        let mut names: Vec<String> = s
            .split(',')
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
    })
}

/// Returns true if an MCP server entry is already proxied through `gate mcp`.
/// Handles both claude-code format { "command": "gate", "args": ["mcp", ...] }
/// and opencode format { "command": ["gate", "mcp", ...] }.
fn is_gate_mcp_proxy(entry: &Value) -> bool {
    let cmd = entry.get("command");
    // claude-code: command is the string "gate", args[0] is "mcp"
    let claude_format = cmd.and_then(|c| c.as_str()) == Some("gate")
        && entry
            .get("args")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            == Some("mcp");
    // opencode: command is an array ["gate", "mcp", ...]
    let opencode_format = cmd
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.first().and_then(|v| v.as_str()) == Some("gate")
                && arr.get(1).and_then(|v| v.as_str()) == Some("mcp")
        })
        .unwrap_or(false);
    claude_format || opencode_format
}

/// Convert existing MCP servers in a claude-code config (mcpServers key) to gate proxies.
fn wrap_mcp_claude(path: &Path, filter: Option<&[String]>, apply: bool) {
    let settings = read_settings(path);

    let Some(servers) = settings.get("mcpServers").and_then(|v| v.as_object()) else {
        println!("No MCP servers found in {}.", path.display());
        return;
    };

    // (name, upstream_cmd, upstream_args)
    let mut to_wrap: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut already_proxied: Vec<String> = Vec::new();

    for (name, entry) in servers {
        if let Some(f) = filter {
            if !f.contains(name) {
                continue;
            }
        }
        if is_gate_mcp_proxy(entry) {
            already_proxied.push(name.clone());
            continue;
        }
        let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) else {
            continue;
        };
        let args: Vec<String> = entry
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        to_wrap.push((name.clone(), cmd.to_string(), args));
    }

    warn_unknown_servers(filter, servers.keys().map(String::as_str));
    print_wrap_plan(&to_wrap, &already_proxied, path, apply);

    if !apply || to_wrap.is_empty() {
        return;
    }

    let mut updated = settings.clone();
    for (name, cmd, args) in &to_wrap {
        let new_args: Vec<Value> = std::iter::once(json!("mcp"))
            .chain(std::iter::once(json!("--")))
            .chain(std::iter::once(json!(cmd)))
            .chain(args.iter().map(|s| json!(s)))
            .collect();
        if let Some(entry) = updated["mcpServers"][name.as_str()].as_object_mut() {
            entry.insert("command".to_string(), json!("gate"));
            entry.insert("args".to_string(), Value::Array(new_args));
        }
    }
    write_atomic(path, &updated)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to write {}: {e}", path.display())));
}

/// Convert existing MCP servers in an opencode config (mcp.servers key) to gate proxies.
fn wrap_mcp_opencode(path: &Path, filter: Option<&[String]>, apply: bool) {
    let settings = if path.exists() {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
            exit_with_error(&format!("failed to read {}: {e}", path.display()))
        });
        serde_json::from_str::<Value>(&content).unwrap_or_else(|e| {
            exit_with_error(&format!("failed to parse {}: {e}", path.display()))
        })
    } else {
        json!({})
    };

    let Some(servers) = settings.get("mcp").and_then(|v| v.as_object()) else {
        println!("No MCP servers found in {}.", path.display());
        return;
    };

    let mut to_wrap: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut already_proxied: Vec<String> = Vec::new();

    for (name, entry) in servers {
        if let Some(f) = filter {
            if !f.contains(name) {
                continue;
            }
        }
        if is_gate_mcp_proxy(entry) {
            already_proxied.push(name.clone());
            continue;
        }
        // opencode command format: array where [0] is the executable
        let Some(command_arr) = entry.get("command").and_then(|c| c.as_array()) else {
            continue;
        };
        let Some(cmd) = command_arr.first().and_then(|v| v.as_str()) else {
            continue;
        };
        let args: Vec<String> = command_arr[1..]
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        to_wrap.push((name.clone(), cmd.to_string(), args));
    }

    warn_unknown_servers(filter, servers.keys().map(String::as_str));
    print_wrap_plan(&to_wrap, &already_proxied, path, apply);

    if !apply || to_wrap.is_empty() {
        return;
    }

    let mut updated = settings.clone();
    for (name, cmd, args) in &to_wrap {
        let new_command: Vec<Value> = std::iter::once(json!("gate"))
            .chain(std::iter::once(json!("mcp")))
            .chain(std::iter::once(json!("--")))
            .chain(std::iter::once(json!(cmd)))
            .chain(args.iter().map(|s| json!(s)))
            .collect();
        if let Some(entry) = updated["mcp"][name.as_str()].as_object_mut() {
            entry.insert("command".to_string(), Value::Array(new_command));
        }
    }
    write_atomic(path, &updated)
        .unwrap_or_else(|e| exit_with_error(&format!("failed to write {}: {e}", path.display())));
}

/// Warn about any names in `filter` that do not appear in `known`.
fn warn_unknown_servers<'a>(filter: Option<&[String]>, known: impl Iterator<Item = &'a str>) {
    let Some(f) = filter else { return };
    let known_set: std::collections::HashSet<&str> = known.collect();
    let unknown: Vec<&str> = f
        .iter()
        .filter(|n| !known_set.contains(n.as_str()))
        .map(String::as_str)
        .collect();
    for name in unknown {
        eprintln!("warning: server '{name}' not found in config");
    }
}

fn print_wrap_plan(
    to_wrap: &[(String, String, Vec<String>)],
    already_proxied: &[String],
    path: &Path,
    apply: bool,
) {
    if to_wrap.is_empty() {
        if already_proxied.is_empty() {
            println!("No MCP servers found in {}.", path.display());
        } else {
            println!(
                "All MCP servers in {} are already proxied through gate.",
                path.display()
            );
        }
        return;
    }

    let total = to_wrap.len() + already_proxied.len();
    let verb = if apply { "Converted" } else { "Would convert" };
    println!(
        "{} {} of {} MCP server{} in {}:\n",
        verb,
        to_wrap.len(),
        total,
        if total == 1 { "" } else { "s" },
        path.display()
    );

    for (name, cmd, args) in to_wrap {
        let before = if args.is_empty() {
            cmd.clone()
        } else {
            format!("{} {}", cmd, args.join(" "))
        };
        let after_parts: Vec<&str> = std::iter::once("gate mcp --")
            .chain(std::iter::once(cmd.as_str()))
            .chain(args.iter().map(String::as_str))
            .collect();
        println!("  {}: {} → {}", name, before, after_parts.join(" "));
    }

    if !already_proxied.is_empty() {
        println!(
            "\n  (already proxied, skipped: {})",
            already_proxied.join(", ")
        );
    }

    if !apply {
        println!("\nRun with --yes to apply.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        (dir, path)
    }

    // insert_hook unit tests

    #[test]
    fn insert_into_empty_object() {
        let settings = json!({});
        let result = insert_hook(settings);
        assert!(matches!(result, HookInsertResult::Done(_)));
        if let HookInsertResult::Done(v) = result {
            assert_eq!(
                v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
                HOOK_COMMAND
            );
        }
    }

    #[test]
    fn already_installed_returns_already() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
                ]
            }
        });
        assert!(matches!(
            insert_hook(settings),
            HookInsertResult::AlreadyInstalled
        ));
    }

    #[test]
    fn replaces_absolute_path_variant() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/gate hook" }] }
                ]
            }
        });
        if let HookInsertResult::Done(v) = insert_hook(settings) {
            let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["hooks"][0]["command"], HOOK_COMMAND);
        } else {
            panic!("expected Done");
        }
    }

    #[test]
    fn preserves_unrelated_entries() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "some-other-hook" }] }
                ]
            }
        });
        if let HookInsertResult::Done(v) = insert_hook(settings) {
            let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(arr.len(), 2);
            let commands: Vec<&str> = arr
                .iter()
                .filter_map(|e| e["hooks"][0]["command"].as_str())
                .collect();
            assert!(commands.contains(&"some-other-hook"));
            assert!(commands.contains(&HOOK_COMMAND));
        } else {
            panic!("expected Done");
        }
    }

    #[test]
    fn non_array_pretu_is_replaced() {
        let settings = json!({ "hooks": { "PreToolUse": "unexpected_string" } });
        if let HookInsertResult::Done(v) = insert_hook(settings) {
            assert!(v["hooks"]["PreToolUse"].is_array());
        } else {
            panic!("expected Done");
        }
    }

    // run_with_path integration tests

    #[test]
    fn creates_settings_when_file_missing() {
        let (_dir, path) = tmp_path();
        run_with_path(&path);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            HOOK_COMMAND
        );
    }

    #[test]
    fn idempotent_on_second_run() {
        let (_dir, path) = tmp_path();
        run_with_path(&path);
        run_with_path(&path);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        let gate_count = arr.iter().filter(|e| entry_has_gate_hook(e)).count();
        assert_eq!(gate_count, 1);
    }

    #[test]
    fn replaces_variant_on_disk() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/gate hook" }] }
                ]
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        run_with_path(&path);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], HOOK_COMMAND);
    }

    #[test]
    fn creates_parent_dir_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/subdir/settings.json");
        run_with_path(&path);
        assert!(path.exists());
    }

    #[test]
    fn write_is_valid_json() {
        let (_dir, path) = tmp_path();
        run_with_path(&path);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(serde_json::from_str::<Value>(&contents).is_ok());
    }

    // claude_code_mcp_path

    #[test]
    fn mcp_path_default_scope_uses_home() {
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", "/test/home") };
        let path = claude_code_mcp_path("global").unwrap();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(path, PathBuf::from("/test/home/.claude.json"));
    }

    #[test]
    fn mcp_path_user_scope_uses_home() {
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", "/test/home") };
        let path = claude_code_mcp_path("user").unwrap();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(path, PathBuf::from("/test/home/.claude.json"));
    }

    #[test]
    fn mcp_path_project_scope_is_relative() {
        let path = claude_code_mcp_path("project").unwrap();
        assert_eq!(path, PathBuf::from(".mcp.json"));
    }

    // opencode_config_path

    #[test]
    fn opencode_config_path_global_uses_home() {
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", "/test/home") };
        let path = opencode_config_path("global").unwrap();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(
            path,
            PathBuf::from("/test/home/.config/opencode/opencode.json")
        );
    }

    #[test]
    fn opencode_config_path_user_uses_home() {
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", "/test/home") };
        let path = opencode_config_path("user").unwrap();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(
            path,
            PathBuf::from("/test/home/.config/opencode/opencode.json")
        );
    }

    #[test]
    fn opencode_config_path_project_is_relative() {
        let path = opencode_config_path("project").unwrap();
        assert_eq!(path, PathBuf::from("opencode.json"));
    }

    // register_mcp_server (claude-code, project scope → .mcp.json)

    #[test]
    fn mcp_server_project_scope_written_to_mcp_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["postgres"]["command"], "gate");
        let args = v["mcpServers"]["postgres"]["args"].as_array().unwrap();
        assert_eq!(args[0], "mcp");
        assert_eq!(args[1], "--");
        assert_eq!(args[2], "uvx");
    }

    #[test]
    fn mcp_server_project_scope_preserves_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        let initial = json!({"mcpServers": {"other": {"command": "other", "args": []}}});
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["mcpServers"]["other"].is_object());
        assert!(v["mcpServers"]["postgres"].is_object());
    }

    // register_mcp_server (claude-code, user scope → ~/.claude.json)

    #[test]
    fn mcp_server_written_to_empty_settings() {
        let (_dir, path) = tmp_path();
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["postgres"]["command"], "gate");
        let args = v["mcpServers"]["postgres"]["args"].as_array().unwrap();
        assert_eq!(args[0], "mcp");
        assert_eq!(args[1], "--");
        assert_eq!(args[2], "uvx");
    }

    #[test]
    fn mcp_server_preserves_existing_entries() {
        let (_dir, path) = tmp_path();
        let initial = json!({"mcpServers": {"other": {"command": "other", "args": []}}});
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["mcpServers"]["other"].is_object());
        assert!(v["mcpServers"]["postgres"].is_object());
    }

    #[test]
    fn mcp_server_overwrites_existing_entry_with_same_name() {
        let (_dir, path) = tmp_path();
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres --old");
        register_mcp_server(&path, "postgres", "uvx mcp-server-postgres --new");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let args = v["mcpServers"]["postgres"]["args"].as_array().unwrap();
        assert!(args.iter().any(|a| a.as_str() == Some("--new")));
    }

    // register_mcp_server_opencode

    #[test]
    fn opencode_mcp_server_written_to_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        register_mcp_server_opencode(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcp"]["postgres"]["type"], "local");
        let cmd = v["mcp"]["postgres"]["command"].as_array().unwrap();
        assert_eq!(cmd[0], "gate");
        assert_eq!(cmd[1], "mcp");
        assert_eq!(cmd[2], "--");
        assert_eq!(cmd[3], "uvx");
    }

    #[test]
    fn opencode_mcp_server_merges_with_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        let initial =
            json!({"theme": "dark", "mcp": {"github": {"type": "local", "command": ["gh"]}}});
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        register_mcp_server_opencode(&path, "postgres", "uvx mcp-server-postgres");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert!(v["mcp"]["github"].is_object());
        assert!(v["mcp"]["postgres"].is_object());
    }

    #[test]
    fn opencode_mcp_server_multi_word_cmd_split_into_args() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        register_mcp_server_opencode(&path, "pg", "uvx mcp-server-postgres --db mydb");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let cmd = v["mcp"]["pg"]["command"].as_array().unwrap();
        // gate, mcp, --, uvx, mcp-server-postgres, --db, mydb
        assert_eq!(cmd.len(), 7);
        assert_eq!(cmd[5], "--db");
        assert_eq!(cmd[6], "mydb");
    }

    // is_gate_hook_variant

    #[test]
    fn variant_matches_exact_command() {
        assert!(is_gate_hook_variant("gate hook"));
    }

    #[test]
    fn variant_matches_absolute_path() {
        assert!(is_gate_hook_variant("/usr/local/bin/gate hook"));
    }

    #[test]
    fn variant_does_not_match_other_commands() {
        assert!(!is_gate_hook_variant("gate run -- tkpsql"));
        assert!(!is_gate_hook_variant("some-tool run"));
        assert!(!is_gate_hook_variant(""));
    }

    // is_gate_mcp_proxy

    #[test]
    fn proxy_detected_when_command_is_gate_and_first_arg_is_mcp() {
        let entry = json!({"command": "gate", "args": ["mcp", "--", "uvx", "mcp-server-postgres"]});
        assert!(is_gate_mcp_proxy(&entry));
    }

    #[test]
    fn proxy_not_detected_for_non_gate_command() {
        let entry = json!({"command": "uvx", "args": ["mcp-server-postgres"]});
        assert!(!is_gate_mcp_proxy(&entry));
    }

    #[test]
    fn proxy_not_detected_when_gate_but_no_mcp_arg() {
        let entry = json!({"command": "gate", "args": ["run", "--", "uvx"]});
        assert!(!is_gate_mcp_proxy(&entry));
    }

    // wrap_mcp_claude — dry-run

    #[test]
    fn wrap_mcp_claude_dry_run_does_not_modify_file() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "postgres": {"command": "uvx", "args": ["mcp-server-postgres"], "env": {}}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        wrap_mcp_claude(&path, None, false);
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["mcpServers"]["postgres"]["command"], "uvx");
    }

    #[test]
    fn wrap_mcp_claude_apply_rewrites_command_and_args() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "postgres": {"command": "uvx", "args": ["mcp-server-postgres", "--db", "mydb"], "env": {}}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        wrap_mcp_claude(&path, None, true);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["postgres"]["command"], "gate");
        let args = v["mcpServers"]["postgres"]["args"].as_array().unwrap();
        assert_eq!(args[0], "mcp");
        assert_eq!(args[1], "--");
        assert_eq!(args[2], "uvx");
        assert_eq!(args[3], "mcp-server-postgres");
        assert_eq!(args[4], "--db");
        assert_eq!(args[5], "mydb");
    }

    #[test]
    fn wrap_mcp_claude_apply_preserves_other_fields() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "pg": {"command": "uvx", "args": ["mcp-server-postgres"], "env": {"DB": "prod"}}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        wrap_mcp_claude(&path, None, true);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["pg"]["env"]["DB"], "prod");
    }

    #[test]
    fn wrap_mcp_claude_apply_skips_already_proxied() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "already": {"command": "gate", "args": ["mcp", "--", "uvx", "mcp-server-x"]},
                "new":     {"command": "uvx", "args": ["mcp-server-y"]}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        wrap_mcp_claude(&path, None, true);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // already-proxied entry unchanged
        assert_eq!(v["mcpServers"]["already"]["args"][2], "uvx");
        // new entry converted
        assert_eq!(v["mcpServers"]["new"]["command"], "gate");
    }

    #[test]
    fn wrap_mcp_claude_apply_no_op_when_all_proxied() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "pg": {"command": "gate", "args": ["mcp", "--", "uvx", "mcp-server-postgres"]}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        wrap_mcp_claude(&path, None, true);
        // file must be untouched (no write_atomic called)
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    // wrap_mcp_opencode — apply

    #[test]
    fn wrap_mcp_opencode_apply_rewrites_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        let initial = json!({
            "theme": "dark",
            "mcp": {
                "github": {"type": "local", "command": ["npx", "@mcp/github"]},
                "proxied": {"type": "local", "command": ["gate", "mcp", "--", "uvx", "mcp-server-x"]}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        wrap_mcp_opencode(&path, None, true);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        let cmd = v["mcp"]["github"]["command"].as_array().unwrap();
        assert_eq!(cmd[0], "gate");
        assert_eq!(cmd[1], "mcp");
        assert_eq!(cmd[2], "--");
        assert_eq!(cmd[3], "npx");
        // already-proxied entry unchanged
        let proxied_cmd = v["mcp"]["proxied"]["command"].as_array().unwrap();
        assert_eq!(proxied_cmd[3], "uvx");
    }

    // parse_servers_filter

    #[test]
    fn parse_servers_filter_none_returns_none() {
        assert!(parse_servers_filter(None).is_none());
    }

    #[test]
    fn parse_servers_filter_splits_and_trims() {
        let f = parse_servers_filter(Some("postgres, github , stripe")).unwrap();
        assert_eq!(f, vec!["github", "postgres", "stripe"]); // sorted
    }

    #[test]
    fn parse_servers_filter_deduplicates() {
        let f = parse_servers_filter(Some("postgres,postgres")).unwrap();
        assert_eq!(f, vec!["postgres"]);
    }

    #[test]
    fn parse_servers_filter_ignores_empty_segments() {
        let f = parse_servers_filter(Some(",postgres,,")).unwrap();
        assert_eq!(f, vec!["postgres"]);
    }

    // --servers filter applied to wrap_mcp_claude

    #[test]
    fn wrap_mcp_claude_filter_only_wraps_named_servers() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "postgres": {"command": "uvx", "args": ["mcp-server-postgres"]},
                "github":   {"command": "npx", "args": ["@mcp/github"]},
                "stripe":   {"command": "npx", "args": ["@mcp/stripe"]}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        let filter = parse_servers_filter(Some("postgres,github"));
        wrap_mcp_claude(&path, filter.as_deref(), true);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["postgres"]["command"], "gate");
        assert_eq!(v["mcpServers"]["github"]["command"], "gate");
        // stripe excluded from filter — must remain unchanged
        assert_eq!(v["mcpServers"]["stripe"]["command"], "npx");
    }

    #[test]
    fn wrap_mcp_claude_filter_dry_run_leaves_file_unchanged() {
        let (_dir, path) = tmp_path();
        let initial = json!({
            "mcpServers": {
                "postgres": {"command": "uvx", "args": ["mcp-server-postgres"]},
                "github":   {"command": "npx", "args": ["@mcp/github"]}
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let filter = parse_servers_filter(Some("postgres"));
        wrap_mcp_claude(&path, filter.as_deref(), false);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }
}
