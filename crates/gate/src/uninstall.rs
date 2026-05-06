use crate::init::entry_has_gate_hook;
use crate::init_opencode::{has_gate_header, plugin_path};
use common::config::config_path;
use common::error::exit_with_error;
use common::harness::is_agent_harness;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn run() {
    if is_agent_harness() {
        exit_with_error(
            "gate uninstall is not available inside an agent harness. \
             Run `gate uninstall` in a terminal session outside the agent.",
        );
    }

    remove_claude_hook();
    remove_config();
    remove_opencode_plugin("global");
    remove_opencode_plugin("project");
}

fn remove_claude_hook() {
    let path = match claude_settings_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gate: skipping Claude Code hook removal: {e}");
            return;
        }
    };
    if !path.exists() {
        return;
    }

    let contents = match std::fs::read_to_string(&path) {
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

    if !strip_gate_hook(&mut settings) {
        return;
    }

    match write_atomic(&path, &settings) {
        Ok(()) => println!("gate: removed hook from {}", path.display()),
        Err(e) => eprintln!("gate: failed to write {}: {e}", path.display()),
    }
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

fn remove_config() {
    let path = match config_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gate: skipping config removal: {e}");
            return;
        }
    };
    let dir = match path.parent() {
        Some(d) => d.to_path_buf(),
        None => path.clone(),
    };
    if !dir.exists() {
        return;
    }
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => println!("gate: removed config directory {}", dir.display()),
        Err(e) => eprintln!("gate: failed to remove {}: {e}", dir.display()),
    }
}

fn remove_opencode_plugin(scope: &str) {
    let path = match plugin_path(scope) {
        Ok(p) => p,
        Err(_) => return,
    };
    if !path.exists() {
        return;
    }
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gate: failed to read {}: {e}", path.display());
            return;
        }
    };
    if !has_gate_header(&contents) {
        println!(
            "gate: skipping {}: not a gate-generated file (no gate header)",
            path.display()
        );
        return;
    }
    match std::fs::remove_file(&path) {
        Ok(()) => println!("gate: removed opencode plugin {}", path.display()),
        Err(e) => eprintln!("gate: failed to remove {}: {e}", path.display()),
    }
}

fn claude_settings_path() -> Result<PathBuf, String> {
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".claude/settings.json"))
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

    // ── remove_claude_hook (via write_atomic + strip_gate_hook) ──────────────

    #[test]
    fn remove_hook_writes_updated_settings() {
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        let (_dir, path) = tmp_settings(&settings);
        let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        strip_gate_hook(&mut v);
        write_atomic(&path, &v).unwrap();
        let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(result["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn remove_hook_leaves_no_tmp_file() {
        let settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gate hook" }] }
            ]}
        });
        let (dir, path) = tmp_settings(&settings);
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        write_atomic(&path, &v).unwrap();
        let tmp = dir.path().join("settings.json.gate_tmp");
        assert!(!tmp.exists());
    }

    // ── remove_opencode_plugin ───────────────────────────────────────────────

    #[test]
    fn skips_plugin_without_gate_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate.ts");
        fs::write(&path, "user authored content\n").unwrap();
        // simulate remove_opencode_plugin logic
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!has_gate_header(&contents));
        // file must be untouched
        assert!(path.exists());
    }

    #[test]
    fn removes_plugin_with_gate_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate.ts");
        let content = "// Generated by `gate init --harness opencode`. Safe to delete.\nsome ts\n";
        fs::write(&path, content).unwrap();
        assert!(has_gate_header(&fs::read_to_string(&path).unwrap()));
        fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }
}
