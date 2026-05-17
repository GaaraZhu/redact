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
    let mut found: Vec<String> = Vec::new();

    // Claude Code
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".claude/settings.json");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if v["hooks"]["PreToolUse"]
                        .as_array()
                        .map(|arr| arr.iter().any(crate::init::entry_has_gate_hook))
                        .unwrap_or(false)
                    {
                        found.push(format!("Claude Code ({})", path.display()));
                    }
                }
            }
        }
    }

    // opencode global
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(&home).join(".config/opencode/plugin/gate.ts");
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if crate::init_opencode::has_gate_header(&contents) {
                    found.push(format!("opencode ({})", path.display()));
                }
            }
        }
    }

    // opencode project
    let project_path = PathBuf::from(".opencode/plugin/gate.ts");
    if project_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&project_path) {
            if crate::init_opencode::has_gate_header(&contents) {
                found.push("opencode (.opencode/plugin/gate.ts)".to_string());
            }
        }
    }

    if found.is_empty() {
        println!("No harness integrations detected.");
        println!("Run `gate init` (Claude Code) or `gate init --harness opencode` to install.");
    } else {
        println!("Installed harness integrations:");
        for h in &found {
            println!("  - {h}");
        }
    }
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

    #[test]
    fn valid_regex_compiles() {
        assert!(Regex::new(r"\bID-\d{6}\b").is_ok());
    }

    #[test]
    #[allow(clippy::invalid_regex)]
    fn invalid_regex_fails() {
        assert!(Regex::new(r"[unclosed").is_err());
    }
}
