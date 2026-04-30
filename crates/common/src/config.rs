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

#[derive(Debug, Deserialize, Serialize)]
pub struct ToolConfig {
    pub sql_arg: Option<String>,
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
    #[default]
    Warn,
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

fn config_path() -> Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("REDACT_CONFIG") {
        return Ok(std::path::PathBuf::from(path));
    }
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(std::path::PathBuf::from(home).join(".config/redact/config.yaml"))
}
