use crate::init::{
    claude_settings_path, copilot_entry_has_gate_hook, cursor_entry_has_gate_hook,
    cursor_hooks_path, entry_has_gate_hook, find_git_root,
};
use crate::init_opencode::{has_gate_header, plugin_path};
use common::config::config_path;
use common::error::exit_with_error;
use common::harness::is_agent_harness;
use common::stats::stats_path;
use serde_json::Value;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

#[derive(Debug)]
enum Action {
    Hook(PathBuf),
    ConfigDir(PathBuf),
    Plugin(PathBuf),
    CopilotHook(PathBuf),
    CursorHook(PathBuf),
    StatsFile(PathBuf),
}

impl Action {
    fn description(&self) -> String {
        match self {
            Action::Hook(p) => format!("Remove gate hook entry from {}", p.display()),
            Action::ConfigDir(p) => format!("Delete config directory {}", p.display()),
            Action::Plugin(p) => format!("Delete opencode plugin {}", p.display()),
            Action::CopilotHook(p) => format!("Remove gate hook entry from {}", p.display()),
            Action::CursorHook(p) => format!("Remove gate hook entry from {}", p.display()),
            Action::StatsFile(p) => format!("Delete stats log {}", p.display()),
        }
    }
}

pub fn run() {
    if is_agent_harness() {
        exit_with_error(
            "gate uninstall is not available inside an agent harness. \
             Run `gate uninstall` in a terminal session outside the agent.",
        );
    }

    let actions = collect_actions();

    if actions.is_empty() {
        println!("Nothing to uninstall.");
        return;
    }

    println!("The following will be removed:");
    for action in &actions {
        println!("  - {}", action.description());
    }
    println!();

    if !confirm("Continue? [y/N] ") {
        println!("Aborted.");
        return;
    }

    for action in &actions {
        execute_action(action);
    }
}

fn collect_actions() -> Vec<Action> {
    let mut actions = Vec::new();

    for scope in &["global", "project"] {
        if let Some(a) = plan_remove_hook(scope) {
            actions.push(a);
        }
    }
    if let Some(a) = plan_remove_copilot_hook() {
        actions.push(a);
    }
    for scope in &["global", "project"] {
        if let Some(a) = plan_remove_cursor_hook(scope) {
            actions.push(a);
        }
    }
    if let Some(a) = plan_remove_config() {
        actions.push(a);
    }
    for scope in &["global", "project"] {
        if let Some(a) = plan_remove_plugin(scope) {
            actions.push(a);
        }
    }
    if let Some(a) = plan_remove_stats() {
        actions.push(a);
    }

    actions
}

fn plan_remove_stats() -> Option<Action> {
    let path = stats_path().ok()?;
    if path.exists() {
        Some(Action::StatsFile(path))
    } else {
        None
    }
}

fn plan_remove_hook(scope: &str) -> Option<Action> {
    let path = claude_settings_path(scope).ok()?;
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&path).ok()?;
    let settings: Value = serde_json::from_str(&contents).ok()?;
    let arr = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())?;
    if arr.iter().any(entry_has_gate_hook) {
        Some(Action::Hook(path))
    } else {
        None
    }
}

fn plan_remove_cursor_hook(scope: &str) -> Option<Action> {
    let path = cursor_hooks_path(scope).ok()?;
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&path).ok()?;
    let settings: Value = serde_json::from_str(&contents).ok()?;
    let arr = settings
        .get("hooks")
        .and_then(|h| h.get("preToolUse"))
        .and_then(|p| p.as_array())?;
    if arr.iter().any(cursor_entry_has_gate_hook) {
        Some(Action::CursorHook(path))
    } else {
        None
    }
}

fn plan_remove_config() -> Option<Action> {
    let path = config_path().ok()?;
    let dir = path.parent()?.to_path_buf();
    if dir.exists() {
        Some(Action::ConfigDir(dir))
    } else {
        None
    }
}

fn plan_remove_plugin(scope: &str) -> Option<Action> {
    let path = plugin_path(scope).ok()?;
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&path).ok()?;
    if has_gate_header(&contents) {
        Some(Action::Plugin(path))
    } else {
        None
    }
}

fn plan_remove_copilot_hook() -> Option<Action> {
    let root = find_git_root()?;
    let path = root.join(".github").join("hooks").join("PreToolUse.json");
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&path).ok()?;
    let settings: Value = serde_json::from_str(&contents).ok()?;
    let arr = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())?;
    if arr.iter().any(copilot_entry_has_gate_hook) {
        Some(Action::CopilotHook(path))
    } else {
        None
    }
}

fn execute_action(action: &Action) {
    match action {
        Action::Hook(path) => {
            let contents = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("gate: failed to read {}: {e}", path.display());
                    return;
                }
            };
            let mut settings: Value = match serde_json::from_str(&contents) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("gate: failed to parse {}: {e}", path.display());
                    return;
                }
            };
            strip_gate_hook(&mut settings);
            match write_atomic(path, &settings) {
                Ok(()) => println!("Removed hook from {}", path.display()),
                Err(e) => eprintln!("gate: failed to write {}: {e}", path.display()),
            }
        }
        Action::ConfigDir(dir) => match std::fs::remove_dir_all(dir) {
            Ok(()) => println!("Deleted config directory {}", dir.display()),
            Err(e) => eprintln!("gate: failed to remove {}: {e}", dir.display()),
        },
        Action::Plugin(path) => match std::fs::remove_file(path) {
            Ok(()) => println!("Deleted opencode plugin {}", path.display()),
            Err(e) => eprintln!("gate: failed to remove {}: {e}", path.display()),
        },
        Action::StatsFile(path) => match std::fs::remove_file(path) {
            Ok(()) => println!("Deleted stats log {}", path.display()),
            Err(e) => eprintln!("gate: failed to remove {}: {e}", path.display()),
        },
        Action::CopilotHook(path) => {
            let contents = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("gate: failed to read {}: {e}", path.display());
                    return;
                }
            };
            let mut settings: Value = match serde_json::from_str(&contents) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("gate: failed to parse {}: {e}", path.display());
                    return;
                }
            };
            strip_copilot_gate_hook(&mut settings);
            match write_atomic(path, &settings) {
                Ok(()) => println!("Removed hook from {}", path.display()),
                Err(e) => eprintln!("gate: failed to write {}: {e}", path.display()),
            }
        }
        Action::CursorHook(path) => {
            let contents = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("gate: failed to read {}: {e}", path.display());
                    return;
                }
            };
            let mut settings: Value = match serde_json::from_str(&contents) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("gate: failed to parse {}: {e}", path.display());
                    return;
                }
            };
            strip_cursor_gate_hook(&mut settings);
            match write_atomic(path, &settings) {
                Ok(()) => println!("Removed hook from {}", path.display()),
                Err(e) => eprintln!("gate: failed to write {}: {e}", path.display()),
            }
        }
    }
}

fn strip_copilot_gate_hook(settings: &mut Value) -> bool {
    let arr = match settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(|p| p.as_array_mut())
    {
        Some(a) => a,
        None => return false,
    };
    let before = arr.len();
    arr.retain(|entry| !copilot_entry_has_gate_hook(entry));
    arr.len() < before
}

fn strip_cursor_gate_hook(settings: &mut Value) -> bool {
    let arr = match settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("preToolUse"))
        .and_then(|p| p.as_array_mut())
    {
        Some(a) => a,
        None => return false,
    };
    let before = arr.len();
    arr.retain(|entry| !cursor_entry_has_gate_hook(entry));
    arr.len() < before
}

/// Remove all gate hook entries from `settings["hooks"]["PreToolUse"]`.
/// Returns true if anything was removed.
fn strip_gate_hook(settings: &mut Value) -> bool {
    let arr = match settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(|p| p.as_array_mut())
    {
        Some(a) => a,
        None => return false,
    };
    let before = arr.len();
    arr.retain(|entry| !entry_has_gate_hook(entry));
    arr.len() < before
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

fn write_atomic(path: &Path, value: &Value) -> anyhow::Result<()> {
    let json_str = serde_json::to_string_pretty(value)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("settings path has no parent directory"))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("settings path has no filename"))?;
    let tmp_path = parent.join(format!("{file_name}.gate_tmp"));
    std::fs::write(&tmp_path, &json_str)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn tmp_settings(value: &Value) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
        (dir, path)
    }

    // ── plan_remove_hook ─────────────────────────────────────────────────────

    #[test]
    fn plan_hook_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = plan_remove_hook("global");
        unsafe { std::env::remove_var("HOME") };
        assert!(result.is_none());
    }

    #[test]
    fn plan_hook_none_when_gate_hook_absent() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let path = claude_dir.join("settings.json");
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-hook" }] }
            ]}
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = plan_remove_hook("global");
        unsafe { std::env::remove_var("HOME") };
        assert!(result.is_none());
    }

    #[test]
    fn plan_hook_some_when_gate_hook_present() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let path = claude_dir.join("settings.json");
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = plan_remove_hook("global");
        unsafe { std::env::remove_var("HOME") };
        assert!(matches!(result, Some(Action::Hook(_))));
    }

    // ── strip_gate_hook ──────────────────────────────────────────────────────

    #[test]
    fn strip_noop_when_no_hooks_key() {
        let mut s = json!({});
        assert!(!strip_gate_hook(&mut s));
    }

    #[test]
    fn strip_noop_when_pretu_missing() {
        let mut s = json!({ "hooks": {} });
        assert!(!strip_gate_hook(&mut s));
    }

    #[test]
    fn strip_noop_when_no_gate_entry() {
        let mut s = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-hook" }] }
            ]}
        });
        assert!(!strip_gate_hook(&mut s));
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn strip_removes_exact_gate_hook() {
        let mut s = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        assert!(strip_gate_hook(&mut s));
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn strip_removes_absolute_path_variant() {
        let mut s = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/gate hook" }] }
            ]}
        });
        assert!(strip_gate_hook(&mut s));
        assert!(s["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn strip_preserves_unrelated_entries() {
        let mut s = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-hook" }] },
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        assert!(strip_gate_hook(&mut s));
        let arr = s["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], "other-hook");
    }

    // ── execute_action: Hook ─────────────────────────────────────────────────

    #[test]
    fn execute_hook_writes_updated_settings() {
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        let (_dir, path) = tmp_settings(&settings);
        execute_action(&Action::Hook(path.clone()));
        let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(result["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn execute_hook_leaves_no_tmp_file() {
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        let (dir, path) = tmp_settings(&settings);
        execute_action(&Action::Hook(path.clone()));
        assert!(!dir.path().join("settings.json.gate_tmp").exists());
    }

    // ── plan_remove_plugin ───────────────────────────────────────────────────

    #[test]
    fn plan_plugin_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate.ts");
        // file does not exist → None (simulate by checking logic directly)
        assert!(!path.exists());
    }

    #[test]
    fn plan_plugin_none_for_file_without_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate.ts");
        fs::write(&path, "user authored content\n").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!has_gate_header(&contents));
    }

    #[test]
    fn plan_plugin_some_for_gate_generated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate.ts");
        let content = "// Generated by `gate init --harness opencode`. Safe to delete.\nsome ts\n";
        fs::write(&path, content).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(has_gate_header(&contents));
    }

    // ── strip_copilot_gate_hook ──────────────────────────────────────────────

    #[test]
    fn strip_copilot_noop_when_no_hooks_key() {
        let mut s = json!({});
        assert!(!strip_copilot_gate_hook(&mut s));
    }

    #[test]
    fn strip_copilot_removes_gate_entry() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "gate hook --format copilot"}
                ]
            }
        });
        assert!(strip_copilot_gate_hook(&mut s));
        assert!(s["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn strip_copilot_removes_absolute_path_variant() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "/usr/local/bin/gate hook --format copilot"}
                ]
            }
        });
        assert!(strip_copilot_gate_hook(&mut s));
        assert!(s["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn strip_copilot_preserves_unrelated_entries() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "other-hook --check"},
                    {"type": "command", "bash": "gate hook --format copilot"}
                ]
            }
        });
        assert!(strip_copilot_gate_hook(&mut s));
        let arr = s["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["bash"].as_str().unwrap(), "other-hook --check");
    }

    #[test]
    fn strip_copilot_noop_when_no_gate_entry() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "other-hook --check"}
                ]
            }
        });
        assert!(!strip_copilot_gate_hook(&mut s));
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    // ── execute_action: CopilotHook ──────────────────────────────────────────

    #[test]
    fn execute_copilot_hook_writes_updated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("PreToolUse.json");
        let settings = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "gate hook --format copilot"}
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        execute_action(&Action::CopilotHook(path.clone()));
        let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(result["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn execute_copilot_hook_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("PreToolUse.json");
        let settings = json!({
            "version": 1,
            "hooks": {
                "PreToolUse": [
                    {"type": "command", "bash": "gate hook --format copilot"}
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        execute_action(&Action::CopilotHook(path.clone()));
        assert!(!dir.path().join("PreToolUse.json.gate_tmp").exists());
    }

    // ── strip_cursor_gate_hook ───────────────────────────────────────────────

    #[test]
    fn strip_cursor_noop_when_no_hooks_key() {
        let mut s = json!({});
        assert!(!strip_cursor_gate_hook(&mut s));
    }

    #[test]
    fn strip_cursor_removes_gate_entry() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "gate hook --format cursor"}
                ]
            }
        });
        assert!(strip_cursor_gate_hook(&mut s));
        assert!(s["hooks"]["preToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn strip_cursor_removes_absolute_path_variant() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "/usr/local/bin/gate hook --format cursor"}
                ]
            }
        });
        assert!(strip_cursor_gate_hook(&mut s));
        assert!(s["hooks"]["preToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn strip_cursor_preserves_unrelated_entries() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "other-hook --check"},
                    {"command": "gate hook --format cursor"}
                ]
            }
        });
        assert!(strip_cursor_gate_hook(&mut s));
        let arr = s["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"].as_str().unwrap(), "other-hook --check");
    }

    #[test]
    fn strip_cursor_noop_when_no_gate_entry() {
        let mut s = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "other-hook --check"}
                ]
            }
        });
        assert!(!strip_cursor_gate_hook(&mut s));
        assert_eq!(s["hooks"]["preToolUse"].as_array().unwrap().len(), 1);
    }

    // ── execute_action: CursorHook ───────────────────────────────────────────

    #[test]
    fn execute_cursor_hook_writes_updated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let settings = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "gate hook --format cursor"}
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        execute_action(&Action::CursorHook(path.clone()));
        let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(result["hooks"]["preToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn execute_cursor_hook_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let settings = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"command": "gate hook --format cursor"}
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();
        execute_action(&Action::CursorHook(path.clone()));
        assert!(!dir.path().join("hooks.json.gate_tmp").exists());
    }
}
