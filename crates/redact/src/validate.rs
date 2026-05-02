use common::config::Config;
use common::error::exit_with_error;
use common::patterns::BUILTIN_PATTERNS;
use regex::Regex;
use std::collections::HashSet;

const RAW_CLIENTS: &[&str] = &["mysql", "psql"];

pub fn run() {
    let config = Config::load().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "failed to load config: {e}. Run `redact config --init-only` to create a starter config."
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
    fn invalid_regex_fails() {
        assert!(Regex::new(r"[unclosed").is_err());
    }
}
