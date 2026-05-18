pub mod intercept;
mod transport;

use common::config::Config;
use intercept::{
    extract_request_id, is_tools_call_request, is_tracked_tools_call_response,
    make_oversized_error, new_pending_calls, redact_tools_call_response,
};
use std::io::{BufReader, BufWriter};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use transport::{read_line, write_line, Message};

/// Forward SIGTERM to the upstream child process, then let the ctrlc handler exit.
#[cfg(unix)]
fn forward_sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid as i32, 15) }; // 15 = SIGTERM
}

#[cfg(not(unix))]
fn forward_sigterm(_pid: u32) {}

/// Entry point for `gate mcp`. Spawns `upstream` as a child process, wires
/// agent stdio ↔ upstream stdio, and redacts PII from `tools/call` responses
/// before they reach the agent. Never returns normally.
///
/// `name` is the harness's logical name for the server (e.g. `"postgres"`),
/// used to label `gate retro` stats events. When `None`, falls back to the
/// upstream command's basename so existing hand-edited configs still produce
/// a usable label.
pub fn run(name: Option<String>, upstream: Vec<String>) -> ! {
    if upstream.is_empty() {
        eprintln!("[gate-mcp] no upstream command specified");
        std::process::exit(1);
    }

    let full_config = Config::load().unwrap_or_else(|e| {
        eprintln!("[gate-mcp] failed to load config: {e}; using defaults");
        Config::default()
    });
    let max_payload_bytes = full_config.mcp.max_payload_bytes;
    let redact_enabled = full_config.enabled && full_config.mcp.redact_tool_results;
    let stats_enabled = full_config.enabled && full_config.stats.enabled;
    let config = Arc::new(full_config.pii);

    let server_name = Arc::new(name.unwrap_or_else(|| derive_server_name(&upstream)));

    let mut child = Command::new(&upstream[0])
        .args(&upstream[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("[gate-mcp] failed to spawn '{}': {e}", upstream[0]);
            std::process::exit(1);
        });

    let child_pid = child.id();
    ctrlc::set_handler(move || {
        forward_sigterm(child_pid);
        std::process::exit(1);
    })
    .unwrap_or_else(|e| eprintln!("[gate-mcp] failed to register signal handler: {e}"));

    let upstream_stdin = child.stdin.take().unwrap();
    let upstream_stdout = child.stdout.take().unwrap();

    let pending = new_pending_calls();
    let pending_clone = Arc::clone(&pending);
    let config_clone = Arc::clone(&config);
    let server_name_clone = Arc::clone(&server_name);

    // Thread 1: agent stdin → upstream stdin (track tools/call request IDs)
    let t1 = thread::spawn(move || {
        let mut reader = BufReader::new(std::io::stdin());
        let mut writer = BufWriter::new(upstream_stdin);
        loop {
            match read_line(&mut reader) {
                None => break,
                Some(msg) => {
                    if let Message::Json(ref v) = msg {
                        if is_tools_call_request(v) {
                            if let Some(id_key) = extract_request_id(v) {
                                pending.lock().unwrap().insert(id_key);
                            }
                        }
                    }
                    if write_line(&mut writer, &msg).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Thread 2: upstream stdout → agent stdout (intercept tools/call responses)
    let t2 = thread::spawn(move || {
        let mut reader = BufReader::new(upstream_stdout);
        let mut writer = BufWriter::new(std::io::stdout());
        loop {
            match read_line(&mut reader) {
                None => break,
                Some(msg) => {
                    let msg = match msg {
                        Message::Json(v) => {
                            if is_tracked_tools_call_response(&v, &pending_clone) && redact_enabled
                            {
                                let size = serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0);
                                if size > max_payload_bytes {
                                    eprintln!(
                                        "[gate-mcp] blocking oversized payload: {size} B \
                                         exceeds max_payload_bytes {max_payload_bytes} B"
                                    );
                                    Message::Json(make_oversized_error(&v, size, max_payload_bytes))
                                } else {
                                    let record_as = if stats_enabled {
                                        Some(server_name_clone.as_str())
                                    } else {
                                        None
                                    };
                                    Message::Json(redact_tools_call_response(
                                        v,
                                        &config_clone,
                                        record_as,
                                    ))
                                }
                            } else {
                                Message::Json(v)
                            }
                        }
                        raw => raw,
                    };
                    if write_line(&mut writer, &msg).is_err() {
                        break;
                    }
                }
            }
        }
    });

    t1.join().ok();
    t2.join().ok();

    let exit_code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
    std::process::exit(exit_code);
}

/// Derive a stats label from the upstream command when `--name` is not supplied.
/// Strips any path prefix and a common `mcp-server-` prefix so e.g.
/// `["uvx", "mcp-server-postgres"]` yields `postgres`.
fn derive_server_name(upstream: &[String]) -> String {
    let raw = upstream
        .iter()
        .find(|s| !s.is_empty() && !s.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("mcp");
    // Prefer the last positional argument (typically the actual server binary)
    // when the first token is a wrapper like `uvx`, `npx`, `python -m`.
    let candidate = match upstream.iter().rev().find(|s| !s.starts_with('-')) {
        Some(s) if s != raw => s.as_str(),
        _ => raw,
    };
    let basename = std::path::Path::new(candidate)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(candidate);
    basename
        .strip_prefix("mcp-server-")
        .unwrap_or(basename)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|&x| x.to_string()).collect()
    }

    #[test]
    fn derive_name_strips_mcp_server_prefix() {
        assert_eq!(
            derive_server_name(&s(&["uvx", "mcp-server-postgres"])),
            "postgres"
        );
        assert_eq!(
            derive_server_name(&s(&["npx", "mcp-server-github"])),
            "github"
        );
    }

    #[test]
    fn derive_name_falls_back_to_basename() {
        assert_eq!(derive_server_name(&s(&["postgres-mcp"])), "postgres-mcp");
        assert_eq!(derive_server_name(&s(&["/usr/local/bin/foo"])), "foo");
    }

    #[test]
    fn derive_name_handles_empty() {
        assert_eq!(derive_server_name(&s(&[])), "mcp");
    }
}
