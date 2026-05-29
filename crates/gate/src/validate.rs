use common::config::Config;
use common::error::exit_with_error;
use common::patterns::BUILTIN_PATTERNS;
use regex::Regex;
use std::collections::HashSet;
use std::path::PathBuf;

const RAW_CLIENTS: &[&str] = &["mysql", "psql"];

pub fn run() {
    let config = Config::load().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "failed to load config: {e}. Run `gate config --init-only` to create a starter config."
        ));
    });

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Warn on raw clients
    for name in config.tools.keys() {
        if RAW_CLIENTS.contains(&name.as_str()) {
            warnings.push(format!(
                "tool '{name}' is a raw database client — database credentials will be reachable by the AI"
            ));
        }
    }

    // Validate PiiConfig confidence fields
    if !(0.0..=1.0).contains(&config.pii.column_name_boost) {
        errors.push(format!(
            "pii.column_name_boost {} is out of range [0.0, 1.0]",
            config.pii.column_name_boost
        ));
    }
    if !(0.0..=1.0).contains(&config.pii.confidence_threshold) {
        errors.push(format!(
            "pii.confidence_threshold {} is out of range [0.0, 1.0]",
            config.pii.confidence_threshold
        ));
    }

    // Validate custom patterns
    let builtin_names: HashSet<&str> = BUILTIN_PATTERNS.iter().map(|p| p.name).collect();
    for (name, pattern) in &config.pii.patterns {
        if let Err(e) = Regex::new(&pattern.regex) {
            errors.push(format!("pattern '{name}': invalid regex: {e}"));
        }
        if !(0.0..=1.0).contains(&pattern.confidence) {
            errors.push(format!(
                "pattern '{name}': confidence {} is out of range [0.0, 1.0]",
                pattern.confidence
            ));
        }
        if builtin_names.contains(name.as_str()) {
            println!("info: pattern '{name}' overrides a built-in pattern");
        }
    }

    for w in &warnings {
        eprintln!("warning: {w}");
    }

    if errors.is_empty() {
        println!("Config is valid.");
    } else {
        for e in &errors {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }

    println!();
    report_harness_installations();
}

fn report_harness_installations() {
    let mut hooks: Vec<String> = Vec::new();
    let mut mcp_wraps: Vec<String> = Vec::new();
    let in_git_repo = crate::init::find_git_root().is_some();

    // Claude Code
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".claude").join("settings.json");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["PreToolUse"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        hooks.push(format!("Claude Code ({})", path.display()));
                    }
                }
            }
        }
    }

    // opencode global
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home)
            .join(".config")
            .join("opencode")
            .join("plugin")
            .join("gate.ts");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if crate::init_opencode::has_gate_header(&contents) {
                    hooks.push(format!("opencode ({})", path.display()));
                }
            }
        }
    }

    // opencode project
    let project_path = PathBuf::from(".opencode").join("plugin").join("gate.ts");
    if project_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&project_path) {
            if crate::init_opencode::has_gate_header(&contents) {
                hooks.push("opencode (.opencode/plugin/gate.ts)".to_string());
            }
        }
    }

    // Cursor global
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".cursor").join("hooks.json");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["preToolUse"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::cursor_entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        hooks.push(format!("Cursor ({})", path.display()));
                    }
                }
            }
        }
    }

    // Cursor project
    let cursor_project_path = PathBuf::from(".cursor").join("hooks.json");
    if cursor_project_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&cursor_project_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                if v["hooks"]["preToolUse"]
                    .as_array()
                    .map(|arr| arr.iter().any(crate::init::cursor_entry_has_gate_hook))
                    .unwrap_or(false)
                {
                    hooks.push("Cursor (.cursor/hooks.json)".to_string());
                }
            }
        }
    }

    // Gemini CLI global
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".gemini").join("settings.json");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["BeforeTool"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::gemini_entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        hooks.push(format!("Gemini CLI ({})", path.display()));
                    }
                }
            }
        }
    }

    // Gemini CLI project
    let gemini_project_path = PathBuf::from(".gemini").join("settings.json");
    if gemini_project_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&gemini_project_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                if v["hooks"]["BeforeTool"]
                    .as_array()
                    .map(|arr| arr.iter().any(crate::init::gemini_entry_has_gate_hook))
                    .unwrap_or(false)
                {
                    hooks.push("Gemini CLI (.gemini/settings.json)".to_string());
                }
            }
        }
    }

    // Copilot CLI (project-level only)
    if in_git_repo {
        let copilot_path = PathBuf::from(".github")
            .join("hooks")
            .join("PreToolUse.json");
        if copilot_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&copilot_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["PreToolUse"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::copilot_entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        hooks.push(format!("Copilot CLI ({})", copilot_path.display()));
                    }
                }
            }
        }
    }

    // Codex global
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".codex").join("hooks.json");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["PreToolUse"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        hooks.push(format!("Codex ({})", path.display()));
                    }
                }
            }
        }
    }

    // Codex project
    let codex_project_path = PathBuf::from(".codex").join("hooks.json");
    if codex_project_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&codex_project_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                if v["hooks"]["PreToolUse"]
                    .as_array()
                    .map(|arr| arr.iter().any(crate::init::entry_has_gate_hook))
                    .unwrap_or(false)
                {
                    hooks.push("Codex (.codex/hooks.json)".to_string());
                }
            }
        }
    }

    // ── MCP wrap detections ──────────────────────────────────────────────────

    let home = std::env::var("HOME").ok();

    // Claude Code MCP wrap (global): ~/.claude.json
    if let Some(ref h) = home {
        let path = PathBuf::from(h).join(".claude.json");
        if has_gate_mcp_wrap(&path, "mcpServers") {
            mcp_wraps.push(format!("Claude Code ({})", path.display()));
        }
    }

    // Cursor MCP wrap (global): ~/.cursor/mcp.json
    if let Some(ref h) = home {
        let path = PathBuf::from(h).join(".cursor").join("mcp.json");
        if has_gate_mcp_wrap(&path, "mcpServers") {
            mcp_wraps.push(format!("Cursor ({})", path.display()));
        }
    }

    // Cursor MCP wrap (project): .cursor/mcp.json
    let cursor_mcp_project = PathBuf::from(".cursor").join("mcp.json");
    if has_gate_mcp_wrap(&cursor_mcp_project, "mcpServers") {
        mcp_wraps.push("Cursor (.cursor/mcp.json)".to_string());
    }

    // Copilot CLI MCP wrap (global): ~/.copilot/mcp-config.json
    if let Some(ref h) = home {
        let path = PathBuf::from(h).join(".copilot").join("mcp-config.json");
        if has_gate_mcp_wrap(&path, "mcpServers") {
            mcp_wraps.push(format!("Copilot CLI ({})", path.display()));
        }
    }

    // Project MCP wrap (shared by Claude Code and Copilot CLI): .mcp.json
    if has_gate_mcp_wrap(&PathBuf::from(".mcp.json"), "mcpServers") {
        mcp_wraps.push("Claude Code / Copilot CLI (.mcp.json)".to_string());
    }

    // opencode MCP wrap (global): ~/.config/opencode/opencode.json
    if let Some(ref h) = home {
        let path = PathBuf::from(h)
            .join(".config")
            .join("opencode")
            .join("opencode.json");
        if has_gate_mcp_wrap(&path, "mcp") {
            mcp_wraps.push(format!("opencode ({})", path.display()));
        }
    }

    // opencode MCP wrap (project): opencode.json
    if has_gate_mcp_wrap(&PathBuf::from("opencode.json"), "mcp") {
        mcp_wraps.push("opencode (opencode.json)".to_string());
    }

    // Gemini CLI MCP wrap (global): ~/.gemini/settings.json
    if let Some(ref h) = home {
        let path = PathBuf::from(h).join(".gemini").join("settings.json");
        if has_gate_mcp_wrap(&path, "mcpServers") {
            mcp_wraps.push(format!("Gemini CLI ({})", path.display()));
        }
    }

    // Gemini CLI MCP wrap (project): .gemini/settings.json
    let gemini_mcp_project = PathBuf::from(".gemini").join("settings.json");
    if has_gate_mcp_wrap(&gemini_mcp_project, "mcpServers") {
        mcp_wraps.push("Gemini CLI (.gemini/settings.json)".to_string());
    }

    // Codex MCP wrap (global): ~/.codex/config.toml
    if let Some(ref h) = home {
        let path = PathBuf::from(h).join(".codex").join("config.toml");
        if has_gate_mcp_wrap_toml(&path) {
            mcp_wraps.push(format!("Codex ({})", path.display()));
        }
    }

    // Codex MCP wrap (project): .codex/config.toml
    let codex_config_project = PathBuf::from(".codex").join("config.toml");
    if has_gate_mcp_wrap_toml(&codex_config_project) {
        mcp_wraps.push("Codex (.codex/config.toml)".to_string());
    }

    if hooks.is_empty() && mcp_wraps.is_empty() {
        println!("No harness integrations detected.");
        println!("Run `gate init` (Claude Code) or `gate init --harness <opencode|cursor|copilot-cli|codex|gemini>` to install.");
    } else {
        if !hooks.is_empty() {
            println!("Bash hooks:");
            for h in &hooks {
                println!("  - {h}");
            }
        }
        if !mcp_wraps.is_empty() {
            if !hooks.is_empty() {
                println!();
            }
            println!("MCP wraps:");
            for h in &mcp_wraps {
                println!("  - {h}");
            }
        }
    }

    if !in_git_repo {
        println!("\nNote: Project-level integrations (Copilot CLI) can only be detected from within a git repository.");
    }
}

fn has_gate_mcp_wrap(path: &PathBuf, key: &str) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    v.get(key)
        .and_then(|s| s.as_object())
        .map(|servers| servers.values().any(crate::init::is_gate_mcp_proxy))
        .unwrap_or(false)
}

fn has_gate_mcp_wrap_toml(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return false;
    };
    let mcp_servers = match doc.get("mcp_servers").and_then(|s| s.as_table()) {
        Some(t) => t,
        None => return false,
    };
    let found = mcp_servers
        .iter()
        .any(|(_, entry)| crate::init::is_codex_gate_mcp_proxy(entry));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_clients_constant_is_correct() {
        assert!(RAW_CLIENTS.contains(&"mysql"));
        assert!(RAW_CLIENTS.contains(&"psql"));
        assert!(!RAW_CLIENTS.contains(&"tkpsql"));
    }

    #[test]
    fn builtin_names_used_for_collision_detection() {
        let names: HashSet<&str> = BUILTIN_PATTERNS.iter().map(|p| p.name).collect();
        assert!(names.contains("email"));
        assert!(names.contains("ssn"));
        assert!(names.contains("phone"));
        assert!(names.contains("credit_card"));
    }
}
