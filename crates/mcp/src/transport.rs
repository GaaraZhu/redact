use anyhow::Result;
use serde_json::Value;
use std::io::{BufRead, Write};

pub enum Message {
    Json(Value),
    /// Non-JSON line forwarded verbatim (e.g. upstream writes invalid JSON-RPC).
    Raw(String),
}

/// Read the next line from `reader`. Returns `None` on EOF or I/O error.
pub fn read_line<R: BufRead>(reader: &mut R) -> Option<Message> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => {
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                return Some(Message::Raw(String::new()));
            }
            match serde_json::from_str(trimmed) {
                Ok(v) => Some(Message::Json(v)),
                Err(_) => Some(Message::Raw(trimmed.to_string())),
            }
        }
        Err(_) => None,
    }
}

/// Write a message as a single line followed by `\n`, then flush.
pub fn write_line<W: Write>(writer: &mut W, msg: &Message) -> Result<()> {
    match msg {
        Message::Json(v) => {
            let s = serde_json::to_string(v)?;
            writer.write_all(s.as_bytes())?;
        }
        Message::Raw(s) => {
            writer.write_all(s.as_bytes())?;
        }
    }
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
