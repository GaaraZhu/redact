use common::config::config_path;
use common::error::exit_with_error;
use common::harness::is_agent_harness;

pub fn protect() {
    if is_agent_harness() {
        exit_with_error("gate protect is not available inside an agent harness.");
    }
    #[cfg(not(unix))]
    exit_with_error("gate protect is not supported on Windows.");
    #[cfg(unix)]
    protect_unix();
}

pub fn unprotect() {
    if is_agent_harness() {
        exit_with_error("gate unprotect is not available inside an agent harness.");
    }
    #[cfg(not(unix))]
    exit_with_error("gate unprotect is not supported on Windows.");
    #[cfg(unix)]
    unprotect_unix();
}

#[cfg(unix)]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(unix)]
fn protect_unix() {
    use std::os::unix::fs::PermissionsExt;

    if !is_root() {
        exit_with_error("Config is protected. Run: sudo gate protect");
    }

    let path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(&format!("cannot resolve config path: {e}")),
    };

    // Ensure the config file exists before protecting it.
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                exit_with_error(&format!("failed to create config directory: {e}"))
            });
        }
        std::fs::write(&path, crate::starter::STARTER_CONFIG)
            .unwrap_or_else(|e| exit_with_error(&format!("failed to write starter config: {e}")));
    }

    // chmod 644 before chown so the file is readable by the user after protection.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| exit_with_error(&format!("failed to set permissions: {e}")));

    let status = std::process::Command::new("chown")
        .arg("root")
        .arg(&path)
        .status()
        .unwrap_or_else(|e| exit_with_error(&format!("failed to run chown: {e}")));
    if !status.success() {
        exit_with_error("failed to transfer config ownership to root");
    }

    println!("Config protected: {}", path.display());
    println!("Use sudo to modify settings: sudo gate enable/disable/config/allowlist");
}

#[cfg(unix)]
fn unprotect_unix() {
    use std::os::unix::fs::PermissionsExt;

    if !is_root() {
        exit_with_error("Config is protected. Run: sudo gate unprotect");
    }

    let user = std::env::var("SUDO_USER")
        .unwrap_or_else(|_| exit_with_error("Config is protected. Run: sudo gate unprotect"));

    let path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(&format!("cannot resolve config path: {e}")),
    };

    let status = std::process::Command::new("chown")
        .arg(&user)
        .arg(&path)
        .status()
        .unwrap_or_else(|e| exit_with_error(&format!("failed to run chown: {e}")));
    if !status.success() {
        exit_with_error("failed to restore config ownership");
    }

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| exit_with_error(&format!("failed to set permissions: {e}")));

    println!("Config unprotected: {}", path.display());
    println!("You can now modify it directly with gate enable/disable/config/allowlist");
}
