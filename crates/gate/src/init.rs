use common::error::exit_with_error;
use common::harness::is_agent_harness;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const HOOK_COMMAND: &str = "gate hook";

pub fn run(harness: &str, scope: &str, mcp: Option<&str>, mcp_cmd: Option<&str>) {
    if is_agent_harness() {
        exit_with_error(
            "gate init is not available inside an agent harness. \
             Run `gate init` in a terminal session outside the agent.",
        );
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
                let path = match claude_settings_path() {
                    Ok(p) => p,
                    Err(e) => exit_with_error(&format!("cannot resolve settings path: {e}")),
                };
                register_mcp_server(&path, server_name, cmd_str);
            }
            _ => exit_with_error(&format!(
                "MCP registration is only supported for claude-code harness (got '{harness}')"
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
}
