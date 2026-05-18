use common::config::{config_path, Config};
use common::error::exit_with_error;

pub enum Action {
    Add(Vec<String>),
    Remove(Vec<String>),
    List,
}

pub fn run(action: Action) {
    let path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(&format!("cannot resolve config path: {e}")),
    };

    match action {
        Action::List => {
            let config = Config::load().unwrap_or_default();
            let al = config.pii.effective_column_allowlist();
            if al.is_empty() {
                println!("Column allowlist is empty.");
                println!("Run `gate scan --review` to identify false positives.");
            } else {
                println!("Column allowlist ({} entries):", al.len());
                for col in &al {
                    println!("  {col}");
                }
                println!();
                println!("These columns skip name-based PII detection.");
                println!("Value-based checks (Luhn, regex patterns) still apply.");
            }
        }

        Action::Add(columns) => {
            let content = read_config_content(&path);
            let new_content = add_to_allowlist_in_yaml(&content, &columns);
            let added: Vec<&str> = columns
                .iter()
                .map(String::as_str)
                .filter(|c| {
                    let lo = c.to_lowercase();
                    parse_current_allowlist(&content).iter().all(|e| e != &lo)
                })
                .collect();
            if added.is_empty() {
                println!("All specified columns are already in the allowlist. No changes made.");
                return;
            }
            write_atomic(&path, &new_content).unwrap_or_else(|e| {
                if is_permission_denied(&e) {
                    exit_with_error("Config is protected. Run: sudo gate allowlist add ...");
                }
                exit_with_error(&format!("failed to write config: {e}"))
            });
            println!(
                "Added {} column(s) to allowlist: {}",
                added.len(),
                added.join(", ")
            );
            println!("Config updated: {}", path.display());
        }

        Action::Remove(columns) => {
            let content = read_config_content(&path);
            let current = parse_current_allowlist(&content);
            let to_remove: Vec<String> = columns
                .iter()
                .map(|c| c.to_lowercase())
                .filter(|c| current.iter().any(|e| e == c))
                .collect();
            if to_remove.is_empty() {
                println!("None of the specified columns are in the allowlist. No changes made.");
                return;
            }
            let new_content = remove_from_allowlist_in_yaml(&content, &columns);
            write_atomic(&path, &new_content).unwrap_or_else(|e| {
                if is_permission_denied(&e) {
                    exit_with_error("Config is protected. Run: sudo gate allowlist remove ...");
                }
                exit_with_error(&format!("failed to write config: {e}"))
            });
            println!(
                "Removed {} column(s) from allowlist: {}",
                to_remove.len(),
                to_remove.join(", ")
            );
            println!("Config updated: {}", path.display());
        }
    }
}

fn read_config_content(path: &std::path::Path) -> String {
    if path.exists() {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| exit_with_error(&format!("failed to read config: {e}")))
    } else {
        String::new()
    }
}

/// Parse the current column_allowlist from YAML content (for deduplication).
pub fn parse_current_allowlist(content: &str) -> Vec<String> {
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };
    val.get("pii")
        .and_then(|p| p.get("column_allowlist"))
        .and_then(|a| a.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_default()
}

/// Add columns to `column_allowlist` in YAML, preserving all other content.
/// Deduplicates: columns already present are silently skipped.
pub fn add_to_allowlist_in_yaml(content: &str, columns: &[String]) -> String {
    let current = parse_current_allowlist(content);
    let to_add: Vec<String> = columns
        .iter()
        .map(|c| c.to_lowercase())
        .filter(|c| !current.iter().any(|e| e == c))
        .collect();

    if to_add.is_empty() {
        return content.to_string();
    }

    let new_entries: String = to_add.iter().map(|c| format!("    - {c}\n")).collect();

    // Case 1: column_allowlist already exists — append after last list item.
    if let Some(insert_pos) = find_allowlist_insert_pos(content) {
        let (before, after) = content.split_at(insert_pos);
        return format!("{before}{new_entries}{after}");
    }

    // Case 2: pii: exists but no column_allowlist — insert section after pii: line.
    if let Some(insert_pos) = find_pii_insert_pos(content) {
        let (before, after) = content.split_at(insert_pos);
        return format!("{before}  column_allowlist:\n{new_entries}{after}");
    }

    // Case 3: no pii: section — append at end.
    let sep = if content.ends_with('\n') || content.is_empty() {
        ""
    } else {
        "\n"
    };
    format!("{content}{sep}pii:\n  column_allowlist:\n{new_entries}")
}

/// Remove columns from `column_allowlist` in YAML, preserving all other content.
pub fn remove_from_allowlist_in_yaml(content: &str, columns: &[String]) -> String {
    let to_remove: Vec<String> = columns.iter().map(|c| c.to_lowercase()).collect();

    let mut result = String::new();
    let mut in_allowlist = false;

    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);

        if trimmed == "  column_allowlist:" {
            in_allowlist = true;
            result.push_str(line);
        } else if in_allowlist && trimmed.starts_with("    -") {
            let item = trimmed.trim_start_matches("    -").trim().to_lowercase();
            if !to_remove.iter().any(|r| r == &item) {
                result.push_str(line);
            }
            // else: drop this line
        } else {
            in_allowlist = false;
            result.push_str(line);
        }
    }

    result
}

/// Returns the byte offset where new `    - item` lines should be inserted
/// (right after the last existing item under `column_allowlist:`).
fn find_allowlist_insert_pos(content: &str) -> Option<usize> {
    let mut offset = 0usize;
    let mut in_allowlist = false;
    let mut found = false;
    let mut insert_at = 0usize;

    for line in content.split_inclusive('\n') {
        let next_offset = offset + line.len();
        let trimmed = line.trim_end_matches(['\n', '\r']);

        if !in_allowlist && trimmed == "  column_allowlist:" {
            found = true;
            in_allowlist = true;
            insert_at = next_offset;
        } else if in_allowlist {
            if trimmed.starts_with("    -") {
                insert_at = next_offset;
            } else {
                in_allowlist = false;
            }
        }

        offset = next_offset;
    }

    if found {
        Some(insert_at)
    } else {
        None
    }
}

/// Returns the byte offset right after the `pii:\n` line (where to insert `  column_allowlist:`).
fn find_pii_insert_pos(content: &str) -> Option<usize> {
    let mut offset = 0usize;

    for line in content.split_inclusive('\n') {
        let next_offset = offset + line.len();
        let trimmed = line.trim_end_matches(['\n', '\r']);

        if trimmed == "pii:" {
            return Some(next_offset);
        }

        offset = next_offset;
    }
    None
}

pub fn write_atomic(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
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

    // ── parse_current_allowlist ───────────────────────────────────────────────

    #[test]
    fn parse_returns_empty_for_blank_content() {
        assert!(parse_current_allowlist("").is_empty());
    }

    #[test]
    fn parse_returns_empty_when_no_pii_section() {
        assert!(parse_current_allowlist("tools:\n  tkpsql:\n    sql_arg: \"--sql\"\n").is_empty());
    }

    #[test]
    fn parse_returns_empty_when_no_allowlist_key() {
        assert!(parse_current_allowlist("pii:\n  action: warn\n").is_empty());
    }

    #[test]
    fn parse_returns_lowercased_entries() {
        let yaml = "pii:\n  column_allowlist:\n    - City\n    - STATE\n";
        let list = parse_current_allowlist(yaml);
        assert_eq!(list, vec!["city", "state"]);
    }

    // ── add_to_allowlist_in_yaml ──────────────────────────────────────────────

    #[test]
    fn add_to_empty_content_creates_pii_section() {
        let out = add_to_allowlist_in_yaml("", &[s("city")]);
        assert!(out.contains("pii:"));
        assert!(out.contains("column_allowlist:"));
        assert!(out.contains("    - city"));
    }

    #[test]
    fn add_to_existing_pii_section_inserts_allowlist() {
        let yaml = "pii:\n  action: warn\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("city")]);
        assert!(out.contains("  column_allowlist:"));
        assert!(out.contains("    - city"));
        assert!(out.contains("  action: warn"));
    }

    #[test]
    fn add_appends_to_existing_allowlist() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("state")]);
        assert!(out.contains("    - city"));
        assert!(out.contains("    - state"));
    }

    #[test]
    fn add_deduplicates_existing_entry() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("city")]);
        // Should be unchanged
        assert_eq!(out, yaml);
    }

    #[test]
    fn add_deduplicates_case_insensitively() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("City"), s("CITY")]);
        assert_eq!(out, yaml);
    }

    #[test]
    fn add_multiple_columns_at_once() {
        let out = add_to_allowlist_in_yaml("", &[s("city"), s("state"), s("province")]);
        assert!(out.contains("    - city"));
        assert!(out.contains("    - state"));
        assert!(out.contains("    - province"));
    }

    #[test]
    fn add_preserves_comments_and_other_sections() {
        let yaml =
            "# gate config\ntools:\n  tkpsql:\n    sql_arg: \"--sql\"\npii:\n  action: warn\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("city")]);
        assert!(out.contains("# gate config"));
        assert!(out.contains("tkpsql"));
        assert!(out.contains("action: warn"));
        assert!(out.contains("    - city"));
    }

    #[test]
    fn add_preserves_content_after_allowlist() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n  action: warn\n";
        let out = add_to_allowlist_in_yaml(yaml, &[s("state")]);
        // state inserted after city; action still present after
        let city_pos = out.find("    - city").unwrap();
        let state_pos = out.find("    - state").unwrap();
        let action_pos = out.find("  action: warn").unwrap();
        assert!(city_pos < state_pos);
        assert!(state_pos < action_pos);
    }

    #[test]
    fn add_lowercases_entries() {
        let out = add_to_allowlist_in_yaml("", &[s("CITY"), s("State")]);
        assert!(out.contains("    - city"));
        assert!(out.contains("    - state"));
        assert!(!out.contains("CITY"));
        assert!(!out.contains("State"));
    }

    // ── remove_from_allowlist_in_yaml ─────────────────────────────────────────

    #[test]
    fn remove_deletes_matching_entry() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n    - state\n";
        let out = remove_from_allowlist_in_yaml(yaml, &[s("city")]);
        assert!(!out.contains("    - city"));
        assert!(out.contains("    - state"));
    }

    #[test]
    fn remove_case_insensitive() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n";
        let out = remove_from_allowlist_in_yaml(yaml, &[s("CITY")]);
        assert!(!out.contains("    - city"));
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let yaml = "pii:\n  column_allowlist:\n    - city\n";
        let out = remove_from_allowlist_in_yaml(yaml, &[s("state")]);
        assert_eq!(out, yaml);
    }

    #[test]
    fn remove_preserves_other_sections() {
        let yaml = "tools:\n  tkpsql:\n    sql_arg: \"--sql\"\npii:\n  column_allowlist:\n    - city\n  action: warn\n";
        let out = remove_from_allowlist_in_yaml(yaml, &[s("city")]);
        assert!(out.contains("tkpsql"));
        assert!(out.contains("action: warn"));
        assert!(!out.contains("    - city"));
    }

    // ── round-trip add → remove ───────────────────────────────────────────────

    #[test]
    fn add_then_remove_restores_original() {
        let original = "pii:\n  action: warn\n";
        let added = add_to_allowlist_in_yaml(original, &[s("city")]);
        let restored = remove_from_allowlist_in_yaml(&added, &[s("city")]);
        // The column_allowlist: header remains but the entry is gone — that's acceptable.
        assert!(!restored.contains("    - city"));
        assert!(restored.contains("action: warn"));
    }

    fn s(v: &str) -> String {
        v.to_string()
    }
}
