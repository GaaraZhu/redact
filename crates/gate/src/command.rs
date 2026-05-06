use common::config::Config;

pub(crate) enum ToolMatch {
    /// Tool found directly in the top-level token stream; `idx` is its position.
    Direct { idx: usize, basename: String },
    /// Tool found inside a shell interpreter's `-c` argument (e.g. `sh -c "psql ..."`).
    /// json_tool rewriting is skipped for nested matches — the tool may not exist in the
    /// target environment (remote container or pod).
    Nested { basename: String },
}

/// Scan `tokens` for the first positional token whose basename matches a configured tool.
/// Handles:
/// - env-var prefixes (`KEY=VALUE`)
/// - flag/value skipping (`--flag VALUE`)
/// - `--` as a positional terminator (`kubectl exec pod -- psql ...`)
/// - shell interpreter `-c` recursion (`sh -c "psql ..."`)
pub(crate) fn find_tool_token(tokens: &[String], config: &Config) -> Option<ToolMatch> {
    let mut skip_next = false;
    let mut past_terminator = false;
    for (i, token) in tokens.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token == "--" {
            past_terminator = true;
            continue;
        }
        if !past_terminator {
            if token.contains('=') && !token.starts_with('-') {
                continue; // env-var assignment
            }
            if token.starts_with('-') {
                // --flag=VALUE embeds its value; --flag VALUE does not
                skip_next = !token.contains('=');
                continue;
            }
        }
        let b = token_basename(token);
        if config.tools.contains_key(&b) {
            return Some(ToolMatch::Direct {
                idx: i,
                basename: b,
            });
        }
        if is_shell_interpreter(&b) {
            if let Some(nested_basename) = find_in_shell_c(&tokens[i + 1..], config) {
                return Some(ToolMatch::Nested {
                    basename: nested_basename,
                });
            }
        }
    }
    None
}

/// Look for `-c VALUE` among `tokens` (the slice starting just after the shell interpreter),
/// tokenize VALUE with shell_words, and recursively search for a configured tool.
fn find_in_shell_c(tokens: &[String], config: &Config) -> Option<String> {
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if t == "-c" {
            let inner = tokens.get(i + 1)?;
            let inner_tokens = shell_words::split(inner).ok()?;
            return find_tool_token(&inner_tokens, config).map(|m| match m {
                ToolMatch::Direct { basename, .. } => basename,
                ToolMatch::Nested { basename } => basename,
            });
        }
        // Skip flags and their values so we don't mistake a flag value for `-c`
        if t.starts_with('-') && !t.contains('=') {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn is_shell_interpreter(basename: &str) -> bool {
    matches!(basename, "sh" | "bash" | "zsh" | "dash")
}

pub(crate) fn token_basename(token: &str) -> String {
    std::path::Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token)
        .to_string()
}
