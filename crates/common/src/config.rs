use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)?;
        let config: Config = serde_yaml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse config at {}: {}", path.display(), e))?;
        Ok(config)
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
