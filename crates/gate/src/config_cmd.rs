use common::config::config_path;
use common::error::exit_with_error;
use common::harness::is_agent_harness;
use std::path::Path;

pub fn run(show_path: bool, print_config: bool, init_only: bool) {
    let interactive = !show_path && !print_config && !init_only;
    if interactive && is_agent_harness() {
        exit_with_error("gate config: interactive mode is not available inside an agent harness");
    }
    // Pre-check: if the config is protected, tell the user before launching an editor.
    #[cfg(unix)]
    if interactive {
        if let Ok(p) = config_path() {
            if p.exists() && std::fs::OpenOptions::new().write(true).open(&p).is_err() {
                exit_with_error("Config is protected. Run: sudo gate config");
            }
        }
    }

    let path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(&format!(
            "failed to resolve config path: {e}. Ensure the HOME environment variable is set."
        )),
    };

    run_with_path(show_path, print_config, init_only, &path);
}

fn run_with_path(show_path: bool, print_config: bool, init_only: bool, path: &Path) {
    if show_path {
        println!("{}", path.display());
        return;
    }

    if print_config {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        print!("{}", contents);
        return;
    }

    if !path.exists() {
        write_starter(path);
        println!("Created config at {}", path.display());
    }

    if init_only {
        return;
    }

    // Interactive: launch $VISUAL → $EDITOR → vi
    let editor = resolve_editor();
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .unwrap_or_else(|e| {
            exit_with_error(&format!(
                "failed to launch editor '{editor}': {e}. \
                 Set $VISUAL or $EDITOR to a valid editor path, or edit the file directly."
            ))
        });
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn write_starter(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            exit_with_error(&format!("failed to create config directory: {e}"))
        });
    }
    std::fs::write(path, crate::starter::STARTER_CONFIG).unwrap_or_else(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            exit_with_error("Config is protected. Run: sudo gate config");
        }
        exit_with_error(&format!("failed to write starter config: {e}"))
    });
}

fn resolve_editor() -> String {
    std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("EDITOR").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "notepad".to_string()
            } else {
                "vi".to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn tmp_config() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        (dir, path)
    }

    // Serialize tests that mutate env vars to avoid races with parallel test runner
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn show_path_does_not_write_file() {
        let (_dir, path) = tmp_config();
        run_with_path(true, false, false, &path);
        assert!(!path.exists());
    }

    #[test]
    fn print_config_empty_when_missing() {
        let (_dir, path) = tmp_config();
        run_with_path(false, true, false, &path);
    }

    #[test]
    fn print_config_returns_contents() {
        let (_dir, path) = tmp_config();
        std::fs::write(&path, "pii:\n  action: warn\n").unwrap();
        run_with_path(false, true, false, &path);
    }

    #[test]
    fn init_only_creates_starter_when_missing() {
        let (_dir, path) = tmp_config();
        run_with_path(false, false, true, &path);
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("tkpsql"));
        assert!(contents.contains("tkdbr"));
    }

    #[test]
    fn init_only_does_not_overwrite_existing() {
        let (_dir, path) = tmp_config();
        let original = "pii:\n  action: warn\n";
        std::fs::write(&path, original).unwrap();
        run_with_path(false, false, true, &path);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, original);
    }

    #[test]
    fn init_only_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/config.yaml");
        run_with_path(false, false, true, &path);
        assert!(path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn editor_invoked_via_editor_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (_dir, path) = tmp_config();
        std::fs::write(&path, "").unwrap();
        let saved_visual = std::env::var("VISUAL").ok();
        let saved_editor = std::env::var("EDITOR").ok();
        unsafe {
            std::env::remove_var("VISUAL");
            std::env::set_var("EDITOR", "/usr/bin/true");
        }
        run_with_path(false, false, false, &path);
        unsafe {
            match saved_visual {
                Some(v) => std::env::set_var("VISUAL", v),
                None => std::env::remove_var("VISUAL"),
            }
            match saved_editor {
                Some(v) => std::env::set_var("EDITOR", v),
                None => std::env::remove_var("EDITOR"),
            }
        }
    }

    #[test]
    fn resolve_editor_falls_back_to_platform_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_visual = std::env::var("VISUAL").ok();
        let saved_editor = std::env::var("EDITOR").ok();
        unsafe {
            std::env::remove_var("VISUAL");
            std::env::remove_var("EDITOR");
        }
        let result = resolve_editor();
        unsafe {
            match saved_visual {
                Some(v) => std::env::set_var("VISUAL", v),
                None => std::env::remove_var("VISUAL"),
            }
            match saved_editor {
                Some(v) => std::env::set_var("EDITOR", v),
                None => std::env::remove_var("EDITOR"),
            }
        }
        #[cfg(windows)]
        assert_eq!(result, "notepad");
        #[cfg(not(windows))]
        assert_eq!(result, "vi");
    }

    #[test]
    fn resolve_editor_prefers_visual() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_visual = std::env::var("VISUAL").ok();
        let saved_editor = std::env::var("EDITOR").ok();
        unsafe {
            std::env::set_var("VISUAL", "/usr/bin/vim");
            std::env::set_var("EDITOR", "/usr/bin/nano");
        }
        let result = resolve_editor();
        unsafe {
            match saved_visual {
                Some(v) => std::env::set_var("VISUAL", v),
                None => std::env::remove_var("VISUAL"),
            }
            match saved_editor {
                Some(v) => std::env::set_var("EDITOR", v),
                None => std::env::remove_var("EDITOR"),
            }
        }
        assert_eq!(result, "/usr/bin/vim");
    }

    #[test]
    fn resolve_editor_falls_back_to_editor_if_visual_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_visual = std::env::var("VISUAL").ok();
        let saved_editor = std::env::var("EDITOR").ok();
        unsafe {
            std::env::remove_var("VISUAL");
            std::env::set_var("EDITOR", "/usr/bin/nano");
        }
        let result = resolve_editor();
        unsafe {
            match saved_visual {
                Some(v) => std::env::set_var("VISUAL", v),
                None => std::env::remove_var("VISUAL"),
            }
            match saved_editor {
                Some(v) => std::env::set_var("EDITOR", v),
                None => std::env::remove_var("EDITOR"),
            }
        }
        assert_eq!(result, "/usr/bin/nano");
    }
}
