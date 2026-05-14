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
pub fn run(upstream: Vec<String>) -> ! {
    if upstream.is_empty() {
        eprintln!("[gate-mcp] no upstream command specified");
        std::process::exit(1);
    }

    let full_config = Config::load().unwrap_or_else(|e| {
        eprintln!("[gate-mcp] failed to load config: {e}; using defaults");
        Config::default()
    });
    let max_payload_bytes = full_config.mcp.max_payload_bytes;
    let redact_enabled = full_config.mcp.redact_tool_results;
    let config = Arc::new(full_config.pii);

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
                                    Message::Json(redact_tools_call_response(v, &config_clone))
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
