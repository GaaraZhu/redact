use common::config::config_path;
use common::error::exit_with_error;
use common::harness::is_agent_harness;

pub fn run(enabled: bool) {
    if is_agent_harness() {
        exit_with_error(
            "gate enable/disable is not available inside an agent harness. \
             Run it in a terminal session outside the agent.",
        );
    }

    let path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(&format!("cannot resolve config path: {e}")),
    };

    let content = if path.exists() {
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| exit_with_error(&format!("failed to read config: {e}")))
    } else {
        String::new()
    };

    let new_content = set_enabled_in_yaml(&content, enabled);
    let cmd = if enabled { "enable" } else { "disable" };
    write_atomic(&path, &new_content).unwrap_or_else(|e| {
        if is_permission_denied(&e) {
            exit_with_error(&format!("Config is protected. Run: sudo gate {cmd}"));
        }
        exit_with_error(&format!("failed to write config: {e}"))
    });

    if enabled {
        println!("gate enabled. PII redaction is ON.");
    } else {
        println!("gate disabled. PII redaction is OFF.");
        println!("Run `gate enable` to re-enable.");
    }
}

/// Set or update the top-level `enabled:` key in a YAML string, preserving all other content.
pub fn set_enabled_in_yaml(content: &str, enabled: bool) -> String {
    let new_line = format!("enabled: {}", if enabled { "true" } else { "false" });

    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if !found && line.starts_with("enabled:") {
                found = true;
                new_line.clone()
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.insert(0, new_line);
    }

    let mut result = lines.join("\n");
    // Preserve trailing newline
    if (content.ends_with('\n') || content.is_empty()) && !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn write_atomic(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    // On Unix, rename() checks directory write permission, not the target file's permission.
    // Opening the file for write first gives us the correct EPERM when the file is protected.
    #[cfg(unix)]
    if path.exists() {
        std::fs::OpenOptions::new().write(true).open(path)?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("config path has no filename"))?;
    let tmp = parent.join(format!("{file_name}.gate_tmp"));
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_enabled_true() {
        let input = "enabled: true\ntools:\n  tkpsql:\n    sql_arg: \"--sql\"\n";
        let out = set_enabled_in_yaml(input, false);
        assert!(out.starts_with("enabled: false\n"));
        assert!(out.contains("tkpsql"));
    }

    #[test]
    fn replaces_existing_enabled_false() {
        let input = "enabled: false\npii:\n  action: redact\n";
        let out = set_enabled_in_yaml(input, true);
        assert!(out.starts_with("enabled: true\n"));
        assert!(out.contains("action: redact"));
    }

    #[test]
    fn prepends_when_key_absent() {
        let input = "tools:\n  tkpsql:\n    sql_arg: \"--sql\"\n";
        let out = set_enabled_in_yaml(input, false);
        assert!(out.starts_with("enabled: false\n"));
        assert!(out.contains("tkpsql"));
    }

    #[test]
    fn empty_content_produces_single_line() {
        let out = set_enabled_in_yaml("", false);
        assert_eq!(out, "enabled: false\n");
    }

    #[test]
    fn preserves_trailing_newline() {
        let input = "enabled: true\n";
        let out = set_enabled_in_yaml(input, false);
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn preserves_comments() {
        let input = "# gate config\nenabled: true\n# tools below\ntools:\n";
        let out = set_enabled_in_yaml(input, false);
        assert!(out.contains("# gate config"));
        assert!(out.contains("enabled: false"));
        assert!(out.contains("# tools below"));
    }

    #[test]
    fn does_not_match_indented_enabled() {
        // An indented `enabled:` inside a nested struct must not be touched
        let input = "tools:\n  tkpsql:\n    enabled: true\n";
        let out = set_enabled_in_yaml(input, false);
        // Top-level key should be prepended, indented one unchanged
        assert!(out.starts_with("enabled: false\n"));
        assert!(out.contains("    enabled: true"));
    }
}
