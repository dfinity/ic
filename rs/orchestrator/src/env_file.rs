//! Reader for the environment files that the orchestrator hands to the
//! processes it manages, e.g. `ic-boundary.env` and `ic-gateway.env`.
//!
//! The supported format is the one the `env-file-reader` crate implemented:
//!
//! ```ini
//! # comments run to the end of the line
//! KEY=value
//! export EXPORTED_KEY=value
//! QUOTED_KEY="a value with spaces"
//! EMPTY_KEY=
//! ```
//!
//! Values may be quoted with `"`, `'` or a backtick and may then span multiple
//! lines. Inside a quoted value, `\n` stands for a newline and, for a value in
//! double quotes, `\"` stands for a double quote. Keys and unquoted values may
//! contain any character except whitespace, `=`, `#` and quotes.

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::Path;

/// Parses the environment file at `path`.
///
/// Fails if the file cannot be read, or if its contents are ill-formatted.
pub fn read_file<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>, Error> {
    let content = std::fs::read_to_string(path)?;

    read_str(&content)
}

/// Parses the contents of an environment file.
///
/// Fails if the contents are ill-formatted.
pub fn read_str(content: &str) -> Result<HashMap<String, String>, Error> {
    parse(tokenize(content)?)
}

/// A single lexical element of an environment file, together with the number of
/// the line it starts on (for diagnostics).
#[derive(Debug, PartialEq)]
enum Token {
    /// The `=` separating a key from its value.
    Assign,
    /// The optional `export` keyword preceding a key.
    Export,
    /// A bare word: a key, or an unquoted value.
    Word(String),
    /// The contents of a quoted value, with quotes removed and escape
    /// sequences resolved.
    QuotedWord(String),
    /// A line break, which terminates a key without a value.
    NewLine,
}

/// Characters that may not appear in a bare word.
const WORD_DELIMITERS: [char; 5] = ['=', '#', '"', '\'', '`'];

fn tokenize(content: &str) -> Result<Vec<(usize, Token)>, Error> {
    let mut tokens = Vec::new();
    let mut characters = content.chars().peekable();
    let mut line = 1;

    while let Some(&character) = characters.peek() {
        match character {
            '\n' => {
                let _newline = characters.next();
                tokens.push((line, Token::NewLine));
                line += 1;
            }

            // A comment runs to the end of the line. The line break itself is
            // left for the next iteration, since it is significant.
            '#' => {
                while characters.peek().is_some_and(|&next| next != '\n') {
                    let _commented_out = characters.next();
                }
            }

            character if character.is_whitespace() => {
                let _whitespace = characters.next();
            }

            '=' => {
                let _assign = characters.next();
                tokens.push((line, Token::Assign));
            }

            quote @ ('"' | '\'' | '`') => {
                let _opening_quote = characters.next();
                let start_line = line;
                let mut value = String::new();

                loop {
                    let Some(character) = characters.next() else {
                        return Err(ill_formatted(format!(
                            "unterminated {quote}-quoted value starting on line {start_line}",
                        )));
                    };

                    if character == quote {
                        break;
                    }

                    if character == '\n' {
                        line += 1;
                    }

                    // Only `"`-quoted values may contain an escaped quote; for
                    // the other quote characters the backslash is literal.
                    let is_escaped_quote =
                        character == '\\' && quote == '"' && characters.peek() == Some(&'"');
                    if is_escaped_quote {
                        value.push('"');
                        let _escaped_quote = characters.next();
                        continue;
                    }

                    value.push(character);
                }

                tokens.push((start_line, Token::QuotedWord(value.replace("\\n", "\n"))));
            }

            _ => {
                let mut word = String::new();
                while let Some(&character) = characters.peek() {
                    let is_word_character =
                        !character.is_whitespace() && !WORD_DELIMITERS.contains(&character);
                    if !is_word_character {
                        break;
                    }

                    word.push(character);
                    let _word_character = characters.next();
                }

                if word == "export" {
                    tokens.push((line, Token::Export));
                } else {
                    tokens.push((line, Token::Word(word)));
                }
            }
        }
    }

    Ok(tokens)
}

fn parse(tokens: Vec<(usize, Token)>) -> Result<HashMap<String, String>, Error> {
    let mut env = HashMap::new();
    let mut tokens = tokens.into_iter().peekable();

    while let Some((line, token)) = tokens.next() {
        // Blank lines (and lines holding nothing but a comment) carry no
        // assignment.
        if token == Token::NewLine {
            continue;
        }

        // The `export` keyword, if present, is followed by the key.
        let token = match token {
            Token::Export => match tokens.next() {
                Some((_, token)) => token,
                None => {
                    return Err(ill_formatted(format!(
                        "line {line}: `export` without a key"
                    )));
                }
            },
            token => token,
        };

        let Token::Word(key) = token else {
            return Err(ill_formatted(format!(
                "line {line}: expected a key, found {}",
                describe(&token),
            )));
        };

        match tokens.next() {
            Some((_, Token::Assign)) => {}
            Some((_, token)) => {
                return Err(ill_formatted(format!(
                    "line {line}: expected `=` after key `{key}`, found {}",
                    describe(&token),
                )));
            }
            None => {
                return Err(ill_formatted(format!(
                    "line {line}: expected `=` after key `{key}`, found end of file",
                )));
            }
        }

        // A key whose value is followed directly by a line break, or that ends
        // the file, has an empty value.
        let value = match tokens.next() {
            Some((_, Token::Word(value) | Token::QuotedWord(value))) => value,
            Some((_, Token::NewLine)) | None => String::new(),
            Some((_, token)) => {
                return Err(ill_formatted(format!(
                    "line {line}: expected a value for key `{key}`, found {}",
                    describe(&token),
                )));
            }
        };

        let _overridden_value = env.insert(key, value);
    }

    Ok(env)
}

fn describe(token: &Token) -> String {
    match token {
        Token::Assign => "`=`".to_string(),
        Token::Export => "`export`".to_string(),
        Token::Word(word) => format!("`{word}`"),
        Token::QuotedWord(word) => format!("quoted `{word}`"),
        Token::NewLine => "a line break".to_string(),
    }
}

fn ill_formatted(message: String) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_ok(content: &str) -> HashMap<String, String> {
        read_str(content).expect("environment file should be well-formatted")
    }

    #[test]
    fn parses_simple_assignments() {
        let env = read_ok("KEY=value\nOTHER_KEY=other_value\n");

        assert_eq!(
            env,
            HashMap::from([
                ("KEY".to_string(), "value".to_string()),
                ("OTHER_KEY".to_string(), "other_value".to_string()),
            ]),
        );
    }

    #[test]
    fn parses_ic_boundary_env_file() {
        let env = read_ok(
            r#"LISTEN_HTTPS_PORT="443"
TLS_CERT_PATH="/var/lib/ic/data/ic-boundary-tls.crt"
OBS_METRICS_ADDR="[::]:9324"
"#,
        );

        assert_eq!(
            env,
            HashMap::from([
                ("LISTEN_HTTPS_PORT".to_string(), "443".to_string()),
                (
                    "TLS_CERT_PATH".to_string(),
                    "/var/lib/ic/data/ic-boundary-tls.crt".to_string(),
                ),
                ("OBS_METRICS_ADDR".to_string(), "[::]:9324".to_string()),
            ]),
        );
    }

    #[test]
    fn parses_ic_gateway_env_file() {
        let env = read_ok("LISTEN_PLAIN=[::]:80\nIC_URL=http://127.0.0.1:8080\n");

        assert_eq!(
            env,
            HashMap::from([
                ("LISTEN_PLAIN".to_string(), "[::]:80".to_string()),
                ("IC_URL".to_string(), "http://127.0.0.1:8080".to_string()),
            ]),
        );
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let env = read_ok("# a comment\n\nKEY=value # trailing comment\n\n# another comment");

        assert_eq!(
            env,
            HashMap::from([("KEY".to_string(), "value".to_string())])
        );
    }

    #[test]
    fn parses_exported_keys() {
        let env = read_ok("export KEY=value\nexport OTHER_KEY=\"other value\"\n");

        assert_eq!(
            env,
            HashMap::from([
                ("KEY".to_string(), "value".to_string()),
                ("OTHER_KEY".to_string(), "other value".to_string()),
            ]),
        );
    }

    #[test]
    fn parses_empty_values() {
        let env = read_ok("KEY=\nQUOTED_KEY=\"\"\nLAST_KEY=");

        assert_eq!(
            env,
            HashMap::from([
                ("KEY".to_string(), String::new()),
                ("QUOTED_KEY".to_string(), String::new()),
                ("LAST_KEY".to_string(), String::new()),
            ]),
        );
    }

    #[test]
    fn parses_all_quote_characters() {
        let env = read_ok("A=\"double\"\nB='single'\nC=`backtick`\n");

        assert_eq!(
            env,
            HashMap::from([
                ("A".to_string(), "double".to_string()),
                ("B".to_string(), "single".to_string()),
                ("C".to_string(), "backtick".to_string()),
            ]),
        );
    }

    #[test]
    fn resolves_escape_sequences_in_quoted_values() {
        let env = read_ok(r#"KEY="a \"quoted\" value\nsecond line""#);

        assert_eq!(
            env,
            HashMap::from([(
                "KEY".to_string(),
                "a \"quoted\" value\nsecond line".to_string(),
            )]),
        );
    }

    #[test]
    fn parses_multiline_quoted_values() {
        let env = read_ok("KEY=\"first\nsecond\"\nOTHER_KEY=value\n");

        assert_eq!(
            env,
            HashMap::from([
                ("KEY".to_string(), "first\nsecond".to_string()),
                ("OTHER_KEY".to_string(), "value".to_string()),
            ]),
        );
    }

    #[test]
    fn parses_unicode() {
        let env = read_ok("🦄=💖\n");

        assert_eq!(env, HashMap::from([("🦄".to_string(), "💖".to_string())]));
    }

    #[test]
    fn last_assignment_of_a_key_wins() {
        let env = read_ok("KEY=first\nKEY=second\n");

        assert_eq!(
            env,
            HashMap::from([("KEY".to_string(), "second".to_string())])
        );
    }

    #[test]
    fn fails_on_missing_assignment() {
        let error = read_str("KEY value\n").expect_err("`KEY value` should not parse");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("expected `=`"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn fails_on_unterminated_quote() {
        let error = read_str("KEY=\"value\n").expect_err("an unterminated quote should not parse");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("unterminated"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn fails_on_value_without_key() {
        let error = read_str("=value\n").expect_err("a value without a key should not parse");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("expected a key"),
            "unexpected error: {error}",
        );
    }
}
