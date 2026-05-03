use common::config::Config;

/// Scan `tokens` for the first positional token whose basename matches a configured tool.
/// Skips env-var assignments (KEY=VALUE), flag tokens (starting with `-`), and the token
/// immediately following a space-separated flag (its value). Returns `(index, basename)`.
///
/// This lets `redact` intercept tool invocations regardless of how many wrapper binaries
/// precede the actual tool (e.g. `rtk psql -c "..."` → finds `psql` at index 1).
pub(crate) fn find_tool_token(tokens: &[String], config: &Config) -> Option<(usize, String)> {
    let mut skip_next = false;
    for (i, token) in tokens.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.contains('=') && !token.starts_with('-') {
            continue; // env-var assignment
        }
        if token.starts_with('-') {
            // --flag=VALUE embeds its value; --flag VALUE does not
            skip_next = !token.contains('=');
            continue;
        }
        let b = token_basename(token);
        if config.tools.contains_key(&b) {
            return Some((i, b));
        }
    }
    None
}

pub(crate) fn token_basename(token: &str) -> String {
    std::path::Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token)
        .to_string()
}
