use candid::CandidType;
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A string used as a regex pattern.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct RegexString(pub String);

impl From<&str> for RegexString {
    fn from(value: &str) -> Self {
        RegexString(value.to_string())
    }
}

impl RegexString {
    /// Compile the string into a regular expression.
    ///
    /// This is a relatively expensive operation that's currently not cached.
    pub fn compile(&self) -> Result<Regex, InvalidRegex> {
        Regex::new(&self.0).map_err(|e| InvalidRegex(e.to_string()))
    }

    /// Checks if the given string matches the compiled regex pattern.
    ///
    /// Returns `Ok(true)` if `value` matches, `Ok(false)` if not, or an error if the regex is invalid.
    pub fn try_is_valid(&self, value: &str) -> Result<bool, InvalidRegex> {
        Ok(self.compile()?.is_match(value))
    }
}

/// An error that occurred during parsing or compiling a regular expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidRegex(String);

impl std::error::Error for InvalidRegex {}

impl std::fmt::Display for InvalidRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

/// A regex-based substitution with a pattern and replacement string.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct RegexSubstitution {
    /// The pattern to be matched.
    pub pattern: RegexString,
    /// The string to replace occurrences `pattern` with.
    pub replacement: String,
}

/// Only log entries matching this filter will be recorded.
#[derive(Clone, Debug, Default, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum LogFilter {
    /// All log entries are recorded.
    #[default]
    ShowAll,
    /// No log entries are recorded.
    HideAll,
    /// Only log entries matching this regular expression are recorded.
    ShowPattern(RegexString),
    /// Only log entries not matching this regular expression are recorded.
    HidePattern(RegexString),
}

impl LogFilter {
    /// Returns whether the given message matches the [`LogFilter`].
    pub fn is_match(&self, message: &str) -> bool {
        match self {
            Self::ShowAll => true,
            Self::HideAll => false,
            Self::ShowPattern(regex) => regex
                .try_is_valid(message)
                .expect("Invalid regex in ShowPattern log filter"),
            Self::HidePattern(regex) => !regex
                .try_is_valid(message)
                .expect("Invalid regex in HidePattern log filter"),
        }
    }
}

/// Defines a sorting order for log entries
#[derive(Copy, Clone, Debug, Deserialize, serde::Serialize)]
pub enum Sort {
    /// Log entries are sorted in ascending chronological order, i.e.
    /// from oldest to newest.
    Ascending,
    /// Log entries are sorted in descending chronological order, i.e.
    /// from newest to oldest.
    Descending,
}

impl FromStr for Sort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "asc" => Ok(Sort::Ascending),
            "desc" => Ok(Sort::Descending),
            _ => Err("could not recognize sort order".to_string()),
        }
    }
}
