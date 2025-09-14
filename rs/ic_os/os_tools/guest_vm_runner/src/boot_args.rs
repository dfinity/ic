use anyhow::Result;
use anyhow::bail;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

/// Extracts the value of `boot_args_var_name` from the given config file.
///
/// Supported config format:
/// VARIABLE1=value
/// VARIABLE2="other value" # some comment
/// VARIABLE3='third value'
///
/// read_boot_args(config_path, "VARIABLE2") returns Ok("other value")
pub fn read_boot_args(config: &Path, boot_args_var_name: &str) -> Result<String> {
    let config_contents = std::fs::read_to_string(config)?;
    for line in config_contents.lines().rev() {
        if let Some(result) = try_parse(line, boot_args_var_name) {
            return Ok(result);
        }
    }

    bail!("Variable {boot_args_var_name} not found");
}

fn try_parse(line: &str, boot_args_var_name: &str) -> Option<String> {
    static BOOT_ARGS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?x)                # Enable verbose mode
        ^                          # Start of line
        \s*                        # Optional whitespace
        (\w+)                      # Capture group 1: variable name
        =                          # Equals sign
        (?:                        # Value alternatives:
            "                      #   Double-quoted string
            ((?:[^"\\]|\\.)*)      #   Capture group 2: content with escapes (each token is either none of " or \ or it's an escaped character)
            "                      #   Closing quote
            |                      # OR
            '                      #   Single-quoted string
            ((?:[^'\\]|\\.)*)      #   Capture group 3: content with escapes
            '                      #   Closing quote
            |                      # OR
            ((?:[^\#'"\\\s]|\\.)*)  #   Capture group 4: unquoted until comment or whitespace
        )                          # End value alternatives
        \s*                        # Optional trailing whitespace
        (?:\#.*)?                  # Optional comment
        $                          # End of line
        "#
        ).unwrap()
    });

    let caps = BOOT_ARGS_REGEX.captures(line)?;

    // Verify variable name matches
    if caps.get(1)?.as_str() != boot_args_var_name {
        return None;
    }

    // Extract value: try double-quoted, single-quoted, then unquoted
    let raw_value = caps
        .get(2)
        .or_else(|| caps.get(3))
        .or_else(|| caps.get(4))
        .map(|m| m.as_str())?;

    Some(process_escapes(raw_value))
}

/// Replaces escape sequences: \n, \t, \", \', \\, etc. with their corresponding characters.
fn process_escapes(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some(other) => result.push(other),
                None => result.push('\\'),
            },
            _ => result.push(c),
        }
    }

    result
}

#[cfg(all(test, not(feature = "skip_default_tests")))]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_try_parse_simple_value() {
        assert_eq!(
            try_parse("BOOT_ARGS=simple_value", "BOOT_ARGS"),
            Some("simple_value".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_double_quotes() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS="quoted value""#, "BOOT_ARGS"),
            Some("quoted value".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_single_quotes() {
        assert_eq!(
            try_parse("BOOT_ARGS='single quoted'", "BOOT_ARGS"),
            Some("single quoted".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_escaped_quotes() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS="value with \"escaped\" quotes""#, "BOOT_ARGS"),
            Some(r#"value with "escaped" quotes"#.to_string())
        );
    }

    #[test]
    fn test_try_parse_with_comment() {
        assert_eq!(
            try_parse("BOOT_ARGS=value # this is a comment", "BOOT_ARGS"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_comment_in_quotes() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS="value # not a comment""#, "BOOT_ARGS"),
            Some("value # not a comment".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_whitespace() {
        assert_eq!(try_parse("  BOOT_ARGS=  value  ", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_empty_value() {
        assert_eq!(try_parse("BOOT_ARGS=", "BOOT_ARGS"), Some("".to_string()));
    }

    #[test]
    fn test_try_parse_only_whitespaces() {
        assert_eq!(try_parse("BOOT_ARGS=  ", "BOOT_ARGS"), Some("".to_string()));
    }

    #[test]
    fn test_try_parse_empty_quoted_value() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS="""#, "BOOT_ARGS"),
            Some("".to_string())
        );
    }

    #[test]
    fn test_try_parse_empty_unquoted_escape_char() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS=hello\\world"#, "BOOT_ARGS"),
            Some("hello\\world".to_string())
        );
    }

    #[test]
    fn test_try_parse_empty_unquoted_whitespace() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS=hello\ dear\ world"#, "BOOT_ARGS"),
            Some("hello dear world".to_string())
        );
    }

    #[test]
    fn test_try_parse_wrong_variable() {
        assert_eq!(try_parse("OTHER_VAR=value", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_partial_match() {
        assert_eq!(try_parse("BOOT_ARGS_EXTRA=value", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_no_equals() {
        assert_eq!(try_parse("BOOT_ARGS", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_unclosed_quotes() {
        assert_eq!(try_parse("BOOT_ARGS=\"unclosed quote", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_mixed_quotes() {
        assert_eq!(try_parse("BOOT_ARGS=\"value'", "BOOT_ARGS"), None);
    }

    #[test]
    fn test_try_parse_with_comment_and_spaces() {
        assert_eq!(
            try_parse("BOOT_ARGS=value with spaces   # comment", "BOOT_ARGS"),
            None
        );
    }

    #[test]
    fn test_try_parse_with_comment_no_spaces() {
        assert_eq!(
            try_parse("BOOT_ARGS=value# comment", "BOOT_ARGS"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_try_parse_quoted_whitespace() {
        assert_eq!(
            try_parse(r#"BOOT_ARGS=" whitespace ""#, "BOOT_ARGS"),
            Some(" whitespace ".to_string())
        );
    }

    #[test]
    fn test_try_parse_with_backslash_escapes() {
        assert_eq!(
            try_parse(
                r#"BOOT_ARGS="value\nwith\tescapes \"x\"=\"y\"""#,
                "BOOT_ARGS"
            ),
            Some("value\nwith\tescapes \"x\"=\"y\"".to_string())
        );
    }

    #[test]
    fn test_read_boot_args_success() -> anyhow::Result<()> {
        let temp_file = NamedTempFile::new()?;
        let content = r#"# Configuration file
SOME_OTHER_VAR=other_value
BOOT_ARGS="kernel params here"
# Comment
"#;
        fs::write(temp_file.path(), content)?;

        let result = read_boot_args(temp_file.path(), "BOOT_ARGS")?;
        assert_eq!(result, "kernel params here");
        Ok(())
    }

    #[test]
    fn test_read_boot_args_multiple_lines() -> anyhow::Result<()> {
        let temp_file = NamedTempFile::new()?;
        let content = r#"BOOT_ARGS=first_value
BOOT_ARGS="second_value"
BOOT_ARGS=third_value
"#;
        fs::write(temp_file.path(), content)?;

        // Should return the last match
        let result = read_boot_args(temp_file.path(), "BOOT_ARGS")?;
        assert_eq!(result, "third_value");
        Ok(())
    }

    #[test]
    fn test_read_boot_args_not_found() -> anyhow::Result<()> {
        let temp_file = NamedTempFile::new()?;
        let content = r#"# Configuration file
SOME_OTHER_VAR=other_value
DIFFERENT_VAR="some value"
"#;
        fs::write(temp_file.path(), content)?;

        let result = read_boot_args(temp_file.path(), "BOOT_ARGS");
        assert!(
            result
                .expect_err("Missing var should be error")
                .to_string()
                .contains("Variable BOOT_ARGS not found")
        );
        Ok(())
    }

    #[test]
    fn test_read_boot_args_file_not_found() {
        let result = read_boot_args(Path::new("nonexistent_file.txt"), "BOOT_ARGS");
        assert!(result.is_err());
    }
}
