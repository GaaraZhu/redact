//! Append-only JSONL stats log for `gate retro`.
//!
//! One line per redaction event. Counts and timings only — never values, never
//! SQL, never command lines. Written via single-syscall `O_APPEND` writes so
//! concurrent producers (parallel `gate run` subprocesses and long-lived
//! `gate mcp` proxies) cannot interleave bytes on POSIX or Windows.
//!
//! Failure is never propagated to callers: stats are nice-to-have, and the
//! redaction pipeline must keep working even if the stats file is unwritable.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// One recorded redaction event. Serialised as a single JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix epoch milliseconds. Set by `record()`; callers don't supply it.
    pub ts: u64,
    /// `"bash"` (Gate 1+2 pipeline) or `"mcp"` (MCP proxy).
    pub path: String,
    /// Tool basename (bash path) or MCP server name (mcp path).
    pub tool: String,
    /// Total PII fields redacted in this event.
    pub fields_redacted: usize,
    /// Microseconds gate spent processing this query (Gate 1 parse + Gate 2
    /// redact on the bash path; Gate 2 redact only on the stdin/mcp paths).
    /// Excludes the wrapped tool's own runtime. `#[serde(default)]` keeps
    /// events written before this field was added parseable (they read as 0,
    /// which `gate retro` treats as "no timing recorded").
    #[serde(default)]
    pub overhead_us: u64,
    /// Per-PII-type counts, e.g. `{"email": 23, "ssn": 8}`.
    pub types: HashMap<String, usize>,
}

impl Event {
    /// Build an event with `ts` set to the current wallclock.
    pub fn now(
        path: &str,
        tool: &str,
        fields_redacted: usize,
        overhead_us: u64,
        types: HashMap<String, usize>,
    ) -> Self {
        Self {
            ts: now_millis(),
            path: path.to_string(),
            tool: tool.to_string(),
            fields_redacted,
            overhead_us,
            types,
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve the stats file path.
///
/// Precedence: `GATE_STATS_PATH` env var; otherwise the platform-conventional
/// state/data-local directory under `gate/stats.jsonl`.
pub fn stats_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("GATE_STATS_PATH") {
        return Ok(PathBuf::from(p));
    }
    default_stats_path()
}

#[cfg(target_os = "linux")]
fn default_stats_path() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_STATE_HOME") {
        if !s.is_empty() {
            return Ok(PathBuf::from(s).join("gate").join("stats.jsonl"));
        }
    }
    let home = home_dir()?;
    Ok(home
        .join(".local")
        .join("state")
        .join("gate")
        .join("stats.jsonl"))
}

#[cfg(target_os = "macos")]
fn default_stats_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("gate")
        .join("stats.jsonl"))
}

#[cfg(target_os = "windows")]
fn default_stats_path() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("LOCALAPPDATA") {
        if !s.is_empty() {
            return Ok(PathBuf::from(s).join("gate").join("stats.jsonl"));
        }
    }
    let home = home_dir()?;
    Ok(home
        .join("AppData")
        .join("Local")
        .join("gate")
        .join("stats.jsonl"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn default_stats_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home.join(".gate").join("stats.jsonl"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| anyhow!("cannot resolve home directory"))
}

/// Append one event to the stats file.
///
/// Best-effort: on any failure (disk full, permission denied, antivirus
/// interference) the error is swallowed and the redaction pipeline continues
/// unaffected. Returns `Ok(())` on a successful write, `Err` for diagnostics
/// in callers that want to surface it (most callers should just `let _ =`).
pub fn record(event: &Event) -> Result<()> {
    let path = stats_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut line = serde_json::to_string(event)?;
    line.push('\n');

    write_with_retry(&path, line.as_bytes())
}

#[cfg(unix)]
fn write_with_retry(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(windows)]
fn write_with_retry(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Windows antivirus / search-indexer software can briefly hold an exclusive
    // lock on a file it's scanning, causing `OpenOptions::open` to return
    // ERROR_SHARING_VIOLATION (raw OS error 32). Retry a few times with tiny
    // backoff; if we still can't open, give up silently.
    const MAX_TRIES: u32 = 3;
    const BACKOFF_MS: u64 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;

    for attempt in 0..MAX_TRIES {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                return Ok(());
            }
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) && attempt + 1 < MAX_TRIES {
                    std::thread::sleep(std::time::Duration::from_millis(BACKOFF_MS));
                    continue;
                }
                return Err(e.into());
            }
        }
    }
    Err(anyhow!("write_with_retry: exhausted retries"))
}

#[cfg(not(any(unix, windows)))]
fn write_with_retry(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_stats_path<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = LOCK.lock().unwrap();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // remove the temp file; record() will recreate
        unsafe { std::env::set_var("GATE_STATS_PATH", &path) };
        f(&path);
        unsafe { std::env::remove_var("GATE_STATS_PATH") };
        let _ = std::fs::remove_file(&path);
    }

    fn ev(tool: &str, total: usize, types: &[(&str, usize)]) -> Event {
        Event::now(
            "bash",
            tool,
            total,
            42,
            types.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        )
    }

    #[test]
    fn record_writes_jsonl_line() {
        with_stats_path(|path| {
            record(&ev("tkpsql", 3, &[("email", 2), ("ssn", 1)])).unwrap();
            let contents = std::fs::read_to_string(path).unwrap();
            assert_eq!(contents.matches('\n').count(), 1);
            let parsed: Event = serde_json::from_str(contents.trim()).unwrap();
            assert_eq!(parsed.tool, "tkpsql");
            assert_eq!(parsed.fields_redacted, 3);
            assert_eq!(parsed.types.get("email"), Some(&2));
            assert_eq!(parsed.types.get("ssn"), Some(&1));
        });
    }

    #[test]
    fn legacy_event_without_overhead_field_parses_as_zero() {
        // Events written before `overhead_us` existed must still deserialize.
        let legacy =
            r#"{"ts":1,"path":"bash","tool":"tkpsql","fields_redacted":3,"types":{"email":3}}"#;
        let parsed: Event = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.overhead_us, 0);
        assert_eq!(parsed.fields_redacted, 3);
    }

    #[test]
    fn record_roundtrips_overhead_us() {
        with_stats_path(|path| {
            record(&Event::now("bash", "tkpsql", 1, 1234, HashMap::new())).unwrap();
            let contents = std::fs::read_to_string(path).unwrap();
            let parsed: Event = serde_json::from_str(contents.trim()).unwrap();
            assert_eq!(parsed.overhead_us, 1234);
        });
    }

    #[test]
    fn record_appends_multiple_events() {
        with_stats_path(|path| {
            for i in 0..5 {
                record(&ev("tkpsql", i, &[("email", i)])).unwrap();
            }
            let contents = std::fs::read_to_string(path).unwrap();
            assert_eq!(contents.lines().count(), 5);
            for line in contents.lines() {
                let _parsed: Event = serde_json::from_str(line).unwrap();
            }
        });
    }

    /// Concurrent-write soak: spawn many threads each writing many events to
    /// the same file. The result must be exactly N*M complete, parseable lines
    /// with no torn writes.
    #[test]
    fn concurrent_writes_do_not_interleave() {
        with_stats_path(|path| {
            const THREADS: usize = 16;
            const EVENTS_PER_THREAD: usize = 50;
            let mut handles = Vec::new();
            for t in 0..THREADS {
                handles.push(std::thread::spawn(move || {
                    for i in 0..EVENTS_PER_THREAD {
                        let e = ev(&format!("tool{t}"), i, &[("email", i), ("ssn", t)]);
                        record(&e).unwrap();
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            let contents = std::fs::read_to_string(path).unwrap();
            let lines: Vec<&str> = contents.lines().collect();
            assert_eq!(lines.len(), THREADS * EVENTS_PER_THREAD);
            for line in lines {
                let parsed: Event = serde_json::from_str(line).unwrap_or_else(|e| {
                    panic!("malformed line {line:?}: {e}");
                });
                assert!(parsed.tool.starts_with("tool"));
            }
        });
    }

    #[test]
    fn stats_path_respects_env_var() {
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("GATE_STATS_PATH", "/tmp/gate-stats-test-xyz.jsonl") };
        let p = stats_path().unwrap();
        unsafe { std::env::remove_var("GATE_STATS_PATH") };
        assert_eq!(p, PathBuf::from("/tmp/gate-stats-test-xyz.jsonl"));
    }
}
