//! A minimal INI reader.
//!
//! Supports the subset of the INI format used by IC-OS configuration files:
//!
//! * `[section]` headers; entries before the first header live in the "global" section
//!   (see [`Ini::global`]).
//! * `key = value` entries. Whitespace around the key, the value and the header name is trimmed.
//!   Keys are case-sensitive. The value runs to the end of the line, so it may contain `=`,
//!   `#` or `;`. If a key is repeated within a section, the last value wins.
//! * Comment lines starting with `#` or `;` (after optional leading whitespace) and blank lines
//!   are ignored. Inline comments are *not* supported: `key = value # comment` yields the value
//!   `value # comment`.
//! * `\n` and `\r\n` line endings.
//!
//! Quoting, escape sequences and multi-line values are intentionally not supported; values are
//! taken verbatim.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The key/value pairs of one INI section.
pub type Properties = HashMap<String, String>;

/// A parsed INI file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ini {
    /// Entries that appear before the first `[section]` header.
    global: Properties,
    /// Named sections, in the order they first appear in the file.
    sections: Vec<(String, Properties)>,
}

impl Ini {
    /// Parses INI content from a string.
    pub fn parse(content: &str) -> Result<Self> {
        let mut ini = Ini::default();
        let mut current: Option<usize> = None; // index into `sections`; None = global

        for (line_index, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                let Some(name) = header.strip_suffix(']') else {
                    bail!(
                        "line {}: malformed section header '{}'",
                        line_index + 1,
                        raw_line
                    );
                };
                let name = name.trim();
                let index = match ini.sections.iter().position(|(n, _)| n == name) {
                    Some(index) => index,
                    None => {
                        ini.sections.push((name.to_string(), Properties::new()));
                        ini.sections.len() - 1
                    }
                };
                current = Some(index);
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                bail!(
                    "line {}: expected 'key = value' but found '{}'",
                    line_index + 1,
                    raw_line
                );
            };
            let key = key.trim();
            if key.is_empty() {
                bail!("line {}: missing key in '{}'", line_index + 1, raw_line);
            }

            let properties = match current {
                None => &mut ini.global,
                Some(index) => &mut ini.sections[index].1,
            };
            properties.insert(key.to_string(), value.trim().to_string());
        }

        Ok(ini)
    }

    /// Reads and parses the INI file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read INI file {}", path.display()))?;
        Self::parse(&content)
            .with_context(|| format!("failed to parse INI file {}", path.display()))
    }

    /// Entries that appear before the first `[section]` header.
    pub fn global(&self) -> &Properties {
        &self.global
    }

    /// The named section, if present.
    pub fn section(&self, name: &str) -> Option<&Properties> {
        self.sections
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, properties)| properties)
    }

    /// Iterates over all key/value pairs of all sections (global section first), ignoring
    /// section boundaries.
    pub fn all_properties(&self) -> impl Iterator<Item = (&str, &str)> {
        std::iter::once(&self.global)
            .chain(self.sections.iter().map(|(_, properties)| properties))
            .flat_map(|properties| {
                properties
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(properties: &'a Properties, key: &str) -> Option<&'a str> {
        properties.get(key).map(String::as_str)
    }

    #[test]
    fn parses_flat_key_values_with_comments_and_blank_lines() {
        let ini = Ini::parse(
            "\n\t\r\n# COMMENT          \n; another comment\n   # indented comment\n\n\
             key1=value1\nkey2 = value 2  \n  key3=value3\nempty=\n",
        )
        .unwrap();

        let global = ini.global();
        assert_eq!(get(global, "key1"), Some("value1"));
        assert_eq!(get(global, "key2"), Some("value 2"));
        assert_eq!(get(global, "key3"), Some("value3"));
        assert_eq!(get(global, "empty"), Some(""));
        assert_eq!(get(global, "missing"), None);
        assert_eq!(global.len(), 4);
        assert!(ini.section("host").is_none());
    }

    #[test]
    fn handles_crlf_line_endings() {
        let ini = Ini::parse("key4=value4\r\nkey5=value5\r\n").unwrap();
        assert_eq!(get(ini.global(), "key4"), Some("value4"));
        assert_eq!(get(ini.global(), "key5"), Some("value5"));
    }

    #[test]
    fn parses_sections() {
        let ini = Ini::parse(
            "top=level\n[host]\nipmi_addr = 10.0.0.1\nusername=admin\n[ other ]\nk=v\n\
             [host]\npassword=p#w;d=x\n",
        )
        .unwrap();

        assert_eq!(get(ini.global(), "top"), Some("level"));

        let host = ini.section("host").unwrap();
        assert_eq!(get(host, "ipmi_addr"), Some("10.0.0.1"));
        assert_eq!(get(host, "username"), Some("admin"));
        // Sections with the same name are merged; values may contain '=', '#' and ';'.
        assert_eq!(get(host, "password"), Some("p#w;d=x"));

        assert_eq!(get(ini.section("other").unwrap(), "k"), Some("v"));
        assert!(ini.section("missing").is_none());

        let mut all: Vec<_> = ini.all_properties().collect();
        all.sort();
        assert_eq!(
            all,
            vec![
                ("ipmi_addr", "10.0.0.1"),
                ("k", "v"),
                ("password", "p#w;d=x"),
                ("top", "level"),
                ("username", "admin"),
            ]
        );
    }

    #[test]
    fn last_duplicate_key_wins() {
        let ini = Ini::parse("a=1\na=2\n").unwrap();
        assert_eq!(get(ini.global(), "a"), Some("2"));
    }

    #[test]
    fn keys_are_case_sensitive_and_values_verbatim() {
        let ini = Ini::parse("Key=\"quoted\"\nkey=back\\slash\n").unwrap();
        assert_eq!(get(ini.global(), "Key"), Some("\"quoted\""));
        assert_eq!(get(ini.global(), "key"), Some("back\\slash"));
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(Ini::parse("novalue\n").is_err());
        assert!(Ini::parse("=value\n").is_err());
        assert!(Ini::parse("[unterminated\n").is_err());
    }

    #[test]
    fn empty_input_is_empty_ini() {
        let ini = Ini::parse("").unwrap();
        assert!(ini.global().is_empty());
        assert_eq!(ini.all_properties().count(), 0);
    }
}
