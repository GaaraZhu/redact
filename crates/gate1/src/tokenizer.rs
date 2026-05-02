#[derive(Debug, Clone, PartialEq)]
pub enum Keyword {
    Select,
    From,
    As,
    Distinct,
    With,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Keyword(Keyword),
    Identifier(String),
    /// Contents of a double-quoted or backtick-quoted identifier, with the quotes stripped.
    QuotedIdentifier(String),
    Star,
    Comma,
    LParen,
    RParen,
    Dot,
}

/// Tokenize `sql` into a flat `Vec<Token>`.
///
/// Whitespace, comments (`--` and `/* */`), string literals (`'...'`), and
/// unrecognised characters are consumed and discarded.  Only the tokens needed
/// for SELECT-list column extraction are emitted.
pub fn tokenize(sql: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,

            // Line comment: -- to end of line
            '-' if i + 1 < chars.len() && chars[i + 1] == '-' => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }

            // Block comment: /* ... */
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                if i + 1 < chars.len() {
                    i += 2; // consume closing */
                }
            }

            // Double-quoted identifier: "col"
            '"' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '"' {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                tokens.push(Token::QuotedIdentifier(ident));
                if i < chars.len() {
                    i += 1; // consume closing "
                }
            }

            // Backtick-quoted identifier: `col`
            '`' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '`' {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                tokens.push(Token::QuotedIdentifier(ident));
                if i < chars.len() {
                    i += 1; // consume closing `
                }
            }

            // String literal: skip entire contents (SQL value, not a column name)
            '\'' => {
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\'' {
                        // '' is an escaped single-quote inside a literal
                        if i + 1 < chars.len() && chars[i + 1] == '\'' {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }

            '*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
            }

            // Identifiers and keywords
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let token = match word.to_uppercase().as_str() {
                    "SELECT" => Token::Keyword(Keyword::Select),
                    "FROM" => Token::Keyword(Keyword::From),
                    "AS" => Token::Keyword(Keyword::As),
                    "DISTINCT" => Token::Keyword(Keyword::Distinct),
                    "WITH" => Token::Keyword(Keyword::With),
                    _ => Token::Identifier(word),
                };
                tokens.push(token);
            }

            // Numbers, operators, semi-colons, etc. — not needed for column extraction
            _ => i += 1,
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_identifiers_and_keywords() {
        let toks = tokenize("SELECT id, email FROM users");
        assert_eq!(
            toks,
            vec![
                Token::Keyword(Keyword::Select),
                Token::Identifier("id".into()),
                Token::Comma,
                Token::Identifier("email".into()),
                Token::Keyword(Keyword::From),
                Token::Identifier("users".into()),
            ]
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        let toks = tokenize("select Email from Users");
        assert!(matches!(toks[0], Token::Keyword(Keyword::Select)));
        assert!(matches!(toks[1], Token::Identifier(_)));
        assert!(matches!(toks[2], Token::Keyword(Keyword::From)));
    }

    #[test]
    fn double_quoted_identifier() {
        let toks = tokenize(r#"SELECT "My Col" FROM t"#);
        assert_eq!(toks[1], Token::QuotedIdentifier("My Col".into()));
    }

    #[test]
    fn backtick_quoted_identifier() {
        let toks = tokenize("SELECT `email` FROM t");
        assert_eq!(toks[1], Token::QuotedIdentifier("email".into()));
    }

    #[test]
    fn line_comment_consumed() {
        let toks = tokenize("SELECT email -- the address\n, id FROM t");
        // comment text must not appear as tokens
        assert!(!toks
            .iter()
            .any(|t| matches!(t, Token::Identifier(s) if s == "the")));
        assert!(toks.contains(&Token::Comma));
        assert!(toks.contains(&Token::Identifier("id".into())));
    }

    #[test]
    fn block_comment_consumed() {
        let toks = tokenize("SELECT email /* ignore this */, id FROM t");
        assert!(!toks
            .iter()
            .any(|t| matches!(t, Token::Identifier(s) if s == "ignore")));
        assert!(toks.contains(&Token::Comma));
    }

    #[test]
    fn string_literal_skipped() {
        // Content of 'value' must not produce tokens
        let toks = tokenize("SELECT id FROM t WHERE name = 'Alice Smith'");
        assert!(!toks
            .iter()
            .any(|t| matches!(t, Token::Identifier(s) if s == "Alice")));
    }

    #[test]
    fn qualified_name_produces_dot() {
        let toks = tokenize("u.email");
        assert_eq!(
            toks,
            vec![
                Token::Identifier("u".into()),
                Token::Dot,
                Token::Identifier("email".into()),
            ]
        );
    }

    #[test]
    fn star_and_parens() {
        let toks = tokenize("COUNT(*)");
        assert_eq!(
            toks,
            vec![
                Token::Identifier("COUNT".into()),
                Token::LParen,
                Token::Star,
                Token::RParen,
            ]
        );
    }
}
