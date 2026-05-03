//! Gate 1 — SQL column extractor (best-effort)
//!
//! Extracts column names from a SQL SELECT list so that Gate 2 can force-redact
//! them regardless of value content.  This is **best-effort**: anything missed
//! here is still caught by Gate 2's regex and column-name heuristics.
//!
//! # Known limitations
//!
//! - **Function calls** (`LOWER(email)`, `COALESCE(a, b)`): skipped entirely.
//!   Gate 2 catches PII values via regex; if the alias is generic, value-based
//!   detection is the only protection.
//! - **CTEs**: only the outermost SELECT at paren-depth 0 is analysed.  Columns
//!   referenced solely inside a CTE body are not registered in the plan.
//! - **Subqueries in the SELECT list**: treated as opaque (has parentheses → skip).
//!   Same caveat as CTEs.
//! - **Non-standard dialects**: the tokenizer handles standard SQL and Databricks
//!   SQL.  Vendor-specific syntax (e.g. `$1` positional params) may fall through
//!   to `Unknown`, producing an empty plan — Gate 2 is the safety net.
//! - **`SELECT *` with `wildcard_policy=warn` (default)**: passes the query
//!   through with a warning.  Set `wildcard_policy: reject` to block wildcards.

pub mod tokenizer;

use common::config::{Action, WildcardPolicy};
use common::redactor::RedactPlan;
use tokenizer::{tokenize, Keyword, Token};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ColumnExtraction {
    /// `SELECT *` or `SELECT t.*` — column set is unknown without a schema lookup.
    Wildcard,
    /// Explicit column list, possibly with aliases.
    Columns(Vec<ExtractedColumn>),
    /// SQL could not be parsed confidently (function calls only, no FROM, etc.).
    /// Gate 2 runs with an empty plan.
    Unknown,
}

#[derive(Debug)]
pub struct ExtractedColumn {
    /// The name that will appear as a JSON key in the query result
    /// (alias if `AS` or bare-identifier alias was used; otherwise the column name).
    pub output_name: String,
    /// The pre-alias column name, used as the PII type label in `[PII:<type>]`.
    pub original: String,
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Extract column references from `sql`'s outermost SELECT list.
pub fn extract_columns(sql: &str) -> ColumnExtraction {
    let tokens = tokenize(sql);

    let select_pos = match find_last_select_at_depth_0(&tokens) {
        Some(pos) => pos,
        None => return ColumnExtraction::Unknown,
    };

    let select_list = collect_select_list(&tokens, select_pos);
    if select_list.is_empty() {
        return ColumnExtraction::Unknown;
    }

    let select_list = skip_distinct(select_list);
    let chunks = split_by_comma_at_depth_0(select_list);

    let mut columns = Vec::new();

    for chunk in &chunks {
        if chunk.is_empty() {
            continue;
        }

        // Function call or subquery — anything inside parens is opaque; skip it.
        if chunk
            .iter()
            .any(|t| matches!(t, Token::LParen | Token::RParen))
        {
            continue;
        }

        // Wildcard: SELECT * or SELECT t.*
        // Checked after paren-skip so that COUNT(*) is caught as a function call, not a wildcard.
        if chunk.iter().any(|t| matches!(t, Token::Star)) {
            return ColumnExtraction::Wildcard;
        }

        if let Some(col) = extract_one_column(chunk) {
            columns.push(col);
        }
    }

    if columns.is_empty() {
        ColumnExtraction::Unknown
    } else {
        ColumnExtraction::Columns(columns)
    }
}

/// Build a `RedactPlan` from the column extraction result.
///
/// `denylist` should be the lowercased effective column names from `PiiConfig`
/// (`config.pii.effective_column_names()`).
pub fn build_plan(
    extraction: &ColumnExtraction,
    action: &Action,
    wildcard_policy: &WildcardPolicy,
    denylist: &[String],
) -> RedactPlan {
    let mut plan = RedactPlan::empty();

    match extraction {
        ColumnExtraction::Unknown => {
            // Best-effort: SQL too complex to parse; Gate 2 runs with an empty plan.
        }

        ColumnExtraction::Wildcard => match wildcard_policy {
            WildcardPolicy::Warn => plan.warnings.push(
                "SELECT * encountered; wildcard_policy=warn, Gate 2 is the safety net".to_string(),
            ),
            WildcardPolicy::Reject => plan.rejected = true,
        },

        ColumnExtraction::Columns(cols) => {
            for col in cols {
                // Match against the original column name (what was actually selected),
                // not the alias. The alias becomes the key in forced_columns because
                // that is what appears in the JSON output.
                if !denylist_matches(&col.original, denylist) {
                    continue;
                }
                match action {
                    Action::Redact => {
                        plan.forced_columns
                            .insert(col.output_name.clone(), col.original.clone());
                    }
                    Action::Warn => {
                        plan.warnings.push(format!(
                            "PII column `{}` detected in SELECT list",
                            col.original
                        ));
                    }
                    Action::Reject => {
                        plan.rejected = true;
                        return plan;
                    }
                }
            }
        }
    }

    plan
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns the position of the last `SELECT` keyword found at paren-depth 0.
/// "Last" handles CTEs: `WITH x AS (SELECT ...) SELECT ...` — we want the outer SELECT.
fn find_last_select_at_depth_0(tokens: &[Token]) -> Option<usize> {
    let mut depth: usize = 0;
    let mut last_select = None;

    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.saturating_sub(1),
            Token::Keyword(Keyword::Select) if depth == 0 => last_select = Some(i),
            _ => {}
        }
    }

    last_select
}

/// Collect tokens from right after `select_pos` up to (not including) the
/// first `FROM` keyword at paren-depth 0.  If there is no `FROM` at depth 0
/// (e.g. `SELECT *`), all remaining tokens are returned.
fn collect_select_list(tokens: &[Token], select_pos: usize) -> Vec<Token> {
    let mut result = Vec::new();
    let mut depth: usize = 0;

    for token in &tokens[select_pos + 1..] {
        match token {
            Token::Keyword(Keyword::From) if depth == 0 => break,
            Token::LParen => {
                depth += 1;
                result.push(token.clone());
            }
            Token::RParen => {
                depth = depth.saturating_sub(1);
                result.push(token.clone());
            }
            _ => result.push(token.clone()),
        }
    }

    result
}

/// Remove a leading `DISTINCT` keyword from the select list if present.
fn skip_distinct(tokens: Vec<Token>) -> Vec<Token> {
    match tokens.first() {
        Some(Token::Keyword(Keyword::Distinct)) => tokens[1..].to_vec(),
        _ => tokens,
    }
}

/// Split a flat token list into per-column chunks by commas at paren-depth 0.
fn split_by_comma_at_depth_0(tokens: Vec<Token>) -> Vec<Vec<Token>> {
    let mut chunks: Vec<Vec<Token>> = vec![Vec::new()];
    let mut depth: usize = 0;

    for token in tokens {
        match &token {
            Token::LParen => {
                depth += 1;
                chunks.last_mut().unwrap().push(token);
            }
            Token::RParen => {
                depth = depth.saturating_sub(1);
                chunks.last_mut().unwrap().push(token);
            }
            Token::Comma if depth == 0 => {
                chunks.push(Vec::new());
            }
            _ => {
                chunks.last_mut().unwrap().push(token);
            }
        }
    }

    chunks
}

/// Try to turn a single select-list chunk (no parens, no star) into an
/// `ExtractedColumn`.  Returns `None` if the chunk is unparseable.
fn extract_one_column(chunk: &[Token]) -> Option<ExtractedColumn> {
    // Case 1: explicit alias via AS
    if let Some(as_pos) = chunk
        .iter()
        .position(|t| matches!(t, Token::Keyword(Keyword::As)))
    {
        let col_expr = &chunk[..as_pos];
        let after_as = &chunk[as_pos + 1..];
        let alias = first_ident_str(after_as)?;
        let original = last_ident_str(col_expr)?;
        return Some(ExtractedColumn {
            output_name: alias.to_lowercase(),
            original: original.to_lowercase(),
        });
    }

    // Case 2: bare alias — last two tokens are both identifiers with no dot between them.
    // Example: `SELECT email contact` → chunk is [Ident("email"), Ident("contact")]
    // Counter-example: `SELECT u.email` → chunk is [Ident("u"), Dot, Ident("email")]
    //                  second-to-last is Dot, so no bare alias.
    if chunk.len() >= 2 && is_ident(&chunk[chunk.len() - 1]) && is_ident(&chunk[chunk.len() - 2]) {
        let alias = ident_str(&chunk[chunk.len() - 1]).unwrap();
        let col_expr = &chunk[..chunk.len() - 1];
        let original = last_ident_str(col_expr)?;
        return Some(ExtractedColumn {
            output_name: alias.to_lowercase(),
            original: original.to_lowercase(),
        });
    }

    // Case 3: simple or schema/table-qualified column.
    // Strip all qualifiers: take the last identifier in the chunk.
    // e.g. [Ident("schema"), Dot, Ident("users"), Dot, Ident("email")] → "email"
    let col_name = last_ident_str(chunk)?;
    Some(ExtractedColumn {
        output_name: col_name.to_lowercase(),
        original: col_name.to_lowercase(),
    })
}

fn is_ident(t: &Token) -> bool {
    matches!(t, Token::Identifier(_) | Token::QuotedIdentifier(_))
}

fn ident_str(t: &Token) -> Option<&str> {
    match t {
        Token::Identifier(s) | Token::QuotedIdentifier(s) => Some(s.as_str()),
        _ => None,
    }
}

fn first_ident_str(tokens: &[Token]) -> Option<&str> {
    tokens.iter().find_map(|t| ident_str(t))
}

fn last_ident_str(tokens: &[Token]) -> Option<&str> {
    tokens.iter().rev().find_map(|t| ident_str(t))
}

/// True when `col` (already lowercased) contains any denylist entry as a substring.
fn denylist_matches(col: &str, denylist: &[String]) -> bool {
    denylist.iter().any(|d| col.contains(d.as_str()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use common::config::{Action, WildcardPolicy};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn cols(extraction: ColumnExtraction) -> Vec<ExtractedColumn> {
        match extraction {
            ColumnExtraction::Columns(c) => c,
            other => panic!("expected Columns, got {other:?}"),
        }
    }

    fn denylist() -> Vec<String> {
        // Use the built-in denylist for plan tests.
        common::patterns::COLUMN_DENYLIST
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn assert_wildcard(e: ColumnExtraction) {
        assert!(
            matches!(e, ColumnExtraction::Wildcard),
            "expected Wildcard, got {e:?}"
        );
    }

    fn assert_unknown(e: ColumnExtraction) {
        assert!(
            matches!(e, ColumnExtraction::Unknown),
            "expected Unknown, got {e:?}"
        );
    }

    // ── extract_columns: simple cases ─────────────────────────────────────────

    #[test]
    fn simple_select_two_columns() {
        let c = cols(extract_columns("SELECT id, email FROM users"));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].output_name, "id");
        assert_eq!(c[0].original, "id");
        assert_eq!(c[1].output_name, "email");
        assert_eq!(c[1].original, "email");
    }

    #[test]
    fn as_alias() {
        let c = cols(extract_columns("SELECT email AS contact FROM users"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "contact");
        assert_eq!(c[0].original, "email");
    }

    #[test]
    fn bare_identifier_alias() {
        let c = cols(extract_columns("SELECT email contact FROM users"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "contact");
        assert_eq!(c[0].original, "email");
    }

    #[test]
    fn qualified_column_table_dot_col() {
        let c = cols(extract_columns("SELECT u.email FROM users u"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "email");
        assert_eq!(c[0].original, "email");
    }

    #[test]
    fn schema_table_column_three_part() {
        let c = cols(extract_columns(
            "SELECT schema.users.email FROM schema.users",
        ));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "email");
        assert_eq!(c[0].original, "email");
    }

    #[test]
    fn qualified_column_with_as_alias() {
        let c = cols(extract_columns("SELECT u.email AS contact FROM users u"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "contact");
        assert_eq!(c[0].original, "email");
    }

    #[test]
    fn multiple_pii_columns() {
        let c = cols(extract_columns(
            "SELECT u.email AS contact, u.ssn FROM users u",
        ));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].output_name, "contact");
        assert_eq!(c[0].original, "email");
        assert_eq!(c[1].output_name, "ssn");
        assert_eq!(c[1].original, "ssn");
    }

    // ── extract_columns: wildcards ────────────────────────────────────────────

    #[test]
    fn select_star() {
        assert_wildcard(extract_columns("SELECT * FROM users"));
    }

    #[test]
    fn select_qualified_star() {
        assert_wildcard(extract_columns("SELECT t.* FROM users t"));
    }

    #[test]
    fn select_star_mixed_with_column() {
        // The first chunk is `*` → should return Wildcard before processing `id`.
        assert_wildcard(extract_columns("SELECT *, id FROM users"));
    }

    #[test]
    fn select_star_no_from() {
        assert_wildcard(extract_columns("SELECT *"));
    }

    // ── extract_columns: DISTINCT ─────────────────────────────────────────────

    #[test]
    fn select_distinct_single_column() {
        let c = cols(extract_columns("SELECT DISTINCT email FROM users"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "email");
    }

    #[test]
    fn select_distinct_multiple_columns() {
        let c = cols(extract_columns("SELECT DISTINCT email, ssn FROM users"));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].output_name, "email");
        assert_eq!(c[1].output_name, "ssn");
    }

    // ── extract_columns: function calls ──────────────────────────────────────

    #[test]
    fn function_call_only_returns_unknown() {
        assert_unknown(extract_columns("SELECT LOWER(email) FROM users"));
    }

    #[test]
    fn count_star_only_returns_unknown() {
        assert_unknown(extract_columns("SELECT COUNT(*) FROM users"));
    }

    #[test]
    fn function_call_alongside_plain_column() {
        // The function-call chunk is skipped; the plain column is extracted.
        let c = cols(extract_columns("SELECT id, LOWER(email) FROM users"));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "id");
    }

    #[test]
    fn aggregate_with_plain_column() {
        let c = cols(extract_columns(
            "SELECT id, COUNT(*) FROM users GROUP BY id",
        ));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "id");
    }

    // ── extract_columns: comments ─────────────────────────────────────────────

    #[test]
    fn inline_block_comment() {
        let c = cols(extract_columns(
            "SELECT email /* the address */, id FROM users",
        ));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].output_name, "email");
        assert_eq!(c[1].output_name, "id");
    }

    #[test]
    fn inline_line_comment() {
        let c = cols(extract_columns(
            "SELECT email, -- the address\n id FROM users",
        ));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].output_name, "email");
        assert_eq!(c[1].output_name, "id");
    }

    // ── extract_columns: CTEs and subqueries ──────────────────────────────────

    #[test]
    fn cte_only_outer_select_is_analysed() {
        // ssn is only in the CTE body; the outer SELECT references `id`.
        let c = cols(extract_columns(
            "WITH cte AS (SELECT ssn FROM sensitive) SELECT id FROM cte",
        ));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "id");
    }

    #[test]
    fn subquery_in_select_list_is_skipped() {
        // The subquery chunk has parens → skipped; `email` is still extracted.
        let c = cols(extract_columns(
            "SELECT (SELECT MAX(id) FROM t) AS max_id, email FROM users",
        ));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].output_name, "email");
    }

    // ── extract_columns: edge cases ───────────────────────────────────────────

    #[test]
    fn quoted_identifier_preserved_lowercased() {
        let c = cols(extract_columns(r#"SELECT "Email" AS addr FROM t"#));
        assert_eq!(c[0].output_name, "addr");
        assert_eq!(c[0].original, "email"); // QuotedIdentifier content lowercased
    }

    #[test]
    fn no_select_keyword_returns_unknown() {
        assert_unknown(extract_columns("UPDATE users SET email = 'x'"));
    }

    // ── build_plan: action=Redact ─────────────────────────────────────────────

    #[test]
    fn redact_denylist_match_inserts_forced_column() {
        let extraction = extract_columns("SELECT id, email FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert_eq!(plan.forced_columns.get("email"), Some(&"email".to_string()));
        assert!(!plan.forced_columns.contains_key("id"));
        assert!(!plan.rejected);
    }

    #[test]
    fn redact_alias_stores_alias_as_key_original_as_label() {
        let extraction = extract_columns("SELECT email AS contact FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        // Gate 2 will look up `contact` in forced_columns; the label is `email`.
        assert_eq!(
            plan.forced_columns.get("contact"),
            Some(&"email".to_string())
        );
        assert!(plan.forced_columns.get("email").is_none());
    }

    #[test]
    fn redact_substring_match_in_column_name() {
        // `user_email` contains the denylist entry `email`.
        let extraction = ColumnExtraction::Columns(vec![ExtractedColumn {
            output_name: "user_email".into(),
            original: "user_email".into(),
        }]);
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.forced_columns.contains_key("user_email"));
    }

    #[test]
    fn redact_multiple_columns_only_pii_forced() {
        let extraction = extract_columns("SELECT id, email, ssn FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.forced_columns.contains_key("email"));
        assert!(plan.forced_columns.contains_key("ssn"));
        assert!(!plan.forced_columns.contains_key("id"));
    }

    // ── build_plan: action=Warn ───────────────────────────────────────────────

    #[test]
    fn warn_adds_warning_no_forced_column() {
        let extraction = extract_columns("SELECT email FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Warn,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.forced_columns.is_empty());
        assert!(!plan.warnings.is_empty());
        assert!(!plan.rejected);
    }

    // ── build_plan: action=Reject ─────────────────────────────────────────────

    #[test]
    fn reject_sets_rejected_flag() {
        let extraction = extract_columns("SELECT email FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Reject,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.rejected);
    }

    #[test]
    fn reject_early_return_on_first_pii_column() {
        // Two PII columns; reject should fire on the first and return immediately.
        let extraction = extract_columns("SELECT email, ssn FROM users");
        let plan = build_plan(
            &extraction,
            &Action::Reject,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.rejected);
        // forced_columns must be empty (we never reached the Redact branch).
        assert!(plan.forced_columns.is_empty());
    }

    // ── build_plan: wildcard ──────────────────────────────────────────────────

    #[test]
    fn wildcard_warn_policy_adds_warning() {
        let extraction = ColumnExtraction::Wildcard;
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(!plan.warnings.is_empty());
        assert!(!plan.rejected);
        assert!(plan.forced_columns.is_empty());
    }

    #[test]
    fn wildcard_reject_policy_sets_rejected() {
        let extraction = ColumnExtraction::Wildcard;
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Reject,
            &denylist(),
        );
        assert!(plan.rejected);
    }

    // ── build_plan: Unknown and no-match cases ────────────────────────────────

    #[test]
    fn unknown_extraction_produces_empty_plan() {
        let extraction = ColumnExtraction::Unknown;
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Reject,
            &denylist(),
        );
        assert!(plan.forced_columns.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(!plan.rejected);
    }

    #[test]
    fn no_denylist_match_produces_empty_plan() {
        let extraction = extract_columns("SELECT id, name FROM products");
        let plan = build_plan(
            &extraction,
            &Action::Redact,
            &WildcardPolicy::Warn,
            &denylist(),
        );
        assert!(plan.forced_columns.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(!plan.rejected);
    }
}
