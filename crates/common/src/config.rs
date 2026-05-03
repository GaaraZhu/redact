use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::patterns::COLUMN_DENYLIST;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
    #[serde(default)]
    pub pii: PiiConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ToolConfig {
    pub sql_arg: Option<String>,
    /// When set, the hook rewrites invocations of this tool to use the named
    /// JSON-output wrapper instead (e.g. `psql` → `psql-json`). The wrapper
    /// must accept `--sql <query>` and emit JSON consumable by Gate 2.
    #[serde(default)]
    pub json_tool: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PiiConfig {
    /// Additional column names beyond the built-in denylist. Use `effective_column_names()` to get the merged set.
    #[serde(default)]
    pub column_names: Vec<String>,
    #[serde(default)]
    pub action: Action,
    #[serde(default)]
    pub wildcard_policy: WildcardPolicy,
    #[serde(default)]
    pub patterns: HashMap<String, Pattern>,
    #[serde(default = "default_column_name_boost")]
    pub column_name_boost: f32,
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,
    #[serde(default = "default_redaction")]
    pub redaction: String,
    #[serde(default = "default_true")]
    pub include_summary: bool,
}

#[derive(Debug, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Redact,
    Warn,
    Reject,
}

#[derive(Debug, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WildcardPolicy {
    Warn,
    #[default]
    Reject,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Pattern {
    pub regex: String,
    pub confidence: f32,
}

fn default_column_name_boost() -> f32 {
    0.15
}
fn default_confidence_threshold() -> f32 {
    0.8
}
fn default_redaction() -> String {
    "[PII:{type}]".to_string()
}
fn default_true() -> bool {
    true
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            column_names: Vec::new(),
            action: Action::default(),
            wildcard_policy: WildcardPolicy::default(),
            patterns: HashMap::new(),
            column_name_boost: default_column_name_boost(),
            confidence_threshold: default_confidence_threshold(),
            redaction: default_redaction(),
            include_summary: true,
        }
    }
}

impl PiiConfig {
    /// Returns the merged column denylist: built-in defaults union user-supplied additions.
    /// All names are lowercased. Order: builtins first, then user additions not already present.
    pub fn effective_column_names(&self) -> Vec<String> {
        let mut names: Vec<String> = COLUMN_DENYLIST.iter().map(|s| s.to_string()).collect();
        for name in &self.column_names {
            let lower = name.to_lowercase();
            if !names.iter().any(|n| n == &lower) {
                names.push(lower);
            }
        }
        names
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_from_path(&config_path()?)
    }

    pub(crate) fn load_from_path(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse config at {}: {}", path.display(), e))
    }
}

pub fn config_path() -> Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("REDACT_CONFIG") {
        return Ok(std::path::PathBuf::from(path));
    }
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(std::path::PathBuf::from(home).join(".config/redact/config.yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    static LOCK: Mutex<()> = Mutex::new(());

    fn load_from_yaml(yaml: &str) -> Result<Config> {
        let _guard = LOCK.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        unsafe { std::env::set_var("REDACT_CONFIG", f.path()) };
        let result = Config::load();
        unsafe { std::env::remove_var("REDACT_CONFIG") };
        result
    }

    fn load_missing() -> Result<Config> {
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("REDACT_CONFIG", "/tmp/redact_nonexistent_xyz_abc.yaml") };
        let result = Config::load();
        unsafe { std::env::remove_var("REDACT_CONFIG") };
        result
    }

    #[test]
    fn defaults_when_file_missing() {
        let config = load_missing().unwrap();
        assert_eq!(config.pii.column_name_boost, 0.15);
        assert_eq!(config.pii.confidence_threshold, 0.8);
        assert_eq!(config.pii.redaction, "[PII:{type}]");
        assert!(config.pii.include_summary);
        assert_eq!(config.pii.action, Action::Redact);
        assert_eq!(config.pii.wildcard_policy, WildcardPolicy::Reject);
        assert!(config.tools.is_empty());
        assert!(config.pii.column_names.is_empty());
        assert!(config.pii.patterns.is_empty());
    }

    #[test]
    fn round_trip_parse() {
        let yaml = r#"
tools:
  tkpsql:
    sql_arg: "--sql"
  mysql:
    sql_arg: ~
pii:
  action: warn
  wildcard_policy: warn
  column_name_boost: 0.2
  confidence_threshold: 0.9
  redaction: "[REDACTED:{type}]"
  include_summary: false
  column_names:
    - secret_token
  patterns:
    custom_id:
      regex: "\\bID-\\d{6}\\b"
      confidence: 0.9
"#;
        let config = load_from_yaml(yaml).unwrap();
        assert_eq!(config.tools["tkpsql"].sql_arg, Some("--sql".to_string()));
        assert!(config.tools["mysql"].sql_arg.is_none());
        assert_eq!(config.pii.action, Action::Warn);
        assert_eq!(config.pii.wildcard_policy, WildcardPolicy::Warn);
        assert_eq!(config.pii.column_name_boost, 0.2);
        assert_eq!(config.pii.confidence_threshold, 0.9);
        assert_eq!(config.pii.redaction, "[REDACTED:{type}]");
        assert!(!config.pii.include_summary);
        assert_eq!(config.pii.column_names, vec!["secret_token"]);
        let pat = &config.pii.patterns["custom_id"];
        assert_eq!(pat.regex, r"\bID-\d{6}\b");
        assert_eq!(pat.confidence, 0.9);
    }

    #[test]
    fn partial_yaml_fills_defaults() {
        // Only override one field; all others must stay at their defaults.
        let config = load_from_yaml("pii:\n  action: warn\n").unwrap();
        assert_eq!(config.pii.action, Action::Warn);
        assert_eq!(config.pii.column_name_boost, 0.15);
        assert_eq!(config.pii.confidence_threshold, 0.8);
        assert_eq!(config.pii.redaction, "[PII:{type}]");
        assert!(config.pii.include_summary);
        assert_eq!(config.pii.wildcard_policy, WildcardPolicy::Reject);
        assert!(config.tools.is_empty());
    }

    #[test]
    fn empty_yaml_uses_all_defaults() {
        let config = load_from_yaml("").unwrap();
        assert_eq!(config.pii.column_name_boost, 0.15);
        assert_eq!(config.pii.confidence_threshold, 0.8);
        assert_eq!(config.pii.redaction, "[PII:{type}]");
        assert!(config.pii.include_summary);
    }

    #[test]
    fn malformed_yaml_returns_error() {
        let result = load_from_yaml("pii: {bad: yaml: :: :");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse config"));
    }

    #[test]
    fn unknown_action_variant_is_error() {
        let result = load_from_yaml("pii:\n  action: explode\n");
        assert!(result.is_err());
    }
}
