use std::collections::BTreeSet;

use crate::ssh_access::execute_bash_command;
use serde::{Deserialize, Serialize};
use ssh2::Session;

/// A builder for querying `journalctl` on a remote node over SSH.
///
/// Use the builder methods to configure the query (e.g. limit the number of entries, follow new
/// entries, restrict the time range via cursors), then call [`search`](Self::search) to execute the
/// query and collect matching journal messages.
pub struct JournalStreamer {
    session: Session,
    journalctl_flags: BTreeSet<String>,
    grep_flags: BTreeSet<String>,
    from_cursor: Option<String>,
}

/// Deserialization target for a single JSON record emitted by
/// `journalctl -o json --output-fields='MESSAGE,__CURSOR'`.
#[derive(Deserialize, Serialize)]
struct JournalOutput {
    #[serde(alias = "MESSAGE")]
    message: String,
    #[serde(alias = "__CURSOR")]
    cursor: String,
}

impl JournalStreamer {
    /// Creates a new `JournalStreamer` that will run `journalctl` commands
    /// over the given SSH `session`.
    pub fn new(session: Session) -> Self {
        Self {
            session,
            journalctl_flags: BTreeSet::new(),
            grep_flags: BTreeSet::new(),
            from_cursor: None,
        }
    }

    /// Limits the number of journal entries returned (maps to `journalctl --lines=`).
    pub fn max_lines(mut self, max_lines: usize) -> Self {
        self.journalctl_flags
            .insert(format!("--lines={}", max_lines));
        self.grep_flags.insert(format!("--max-count={}", max_lines));
        self
    }

    /// Enables follow mode (maps to `journalctl --follow`), causing `journalctl` to block and wait
    /// for new entries instead of returning immediately.
    /// Searching for a string after calling this function will return only when the SSH session is
    /// closed, i.e. when the node shuts down or reboots. Even then, it will probably return an
    /// error with `transport read`. Thus, it is recommended to also call `max_lines` to return as
    /// soon as the expected number of lines have been read.
    pub fn follow(mut self) -> Self {
        self.journalctl_flags.insert("--follow".to_string());
        self
    }

    /// Restricts the search to the previous boot's journal entries (maps to `journalctl
    /// --boot=-1`).
    pub fn previous_boot(mut self) -> Self {
        self.journalctl_flags.insert("--boot=-1".to_string());
        self
    }

    /// Anchors subsequent searches to start after the current latest journal entry. This is useful
    /// for ignoring pre-existing log lines and only matching entries that appear after this call.
    ///
    /// Returns an error on transport errors or if the journal is empty and there is no cursor to
    /// anchor to.
    pub fn from_now(mut self) -> anyhow::Result<Self> {
        let (_message, cursor) = Self::new(self.session.clone())
            .max_lines(1)
            .search_and_return_cursors("__CURSOR")?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No journal entries found"))?;

        self.from_cursor = Some(cursor);
        Ok(self)
    }

    /// Searches the journal for the first entry matching `search_regex` and returns the cursor of
    /// that entry. This is useful for anchoring subsequent searches to start or end at a specific
    /// log line.
    ///
    /// Returns an error if no entry matches the regex.
    pub fn get_cursor_at(&self, search_regex: &str) -> anyhow::Result<String> {
        let (_message, cursor) = self
            .search_and_return_cursors(search_regex)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("No journal entries found matching the regex '{search_regex}'")
            })?;

        Ok(cursor)
    }

    /// Executes the configured `journalctl` query, filters the output with `search_regex`, and
    /// returns the matching journal messages.
    pub fn search(&self, search_regex: &str) -> anyhow::Result<Vec<String>> {
        self.search_and_return_cursors(search_regex)
            .map(|iter| iter.into_iter().map(|(message, _cursor)| message).collect())
    }

    /// Builds and executes the `journalctl` command over SSH, parses the JSON output, and returns
    /// `(message, cursor)` pairs for entries matching `search_regex`.
    fn search_and_return_cursors(
        &self,
        search_regex: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let mut command = "journalctl --output json --output-fields='MESSAGE,__CURSOR'".to_string();

        if !self.journalctl_flags.is_empty() {
            command.push(' ');
            command.push_str(&Vec::from_iter(self.journalctl_flags.iter().cloned()).join(" "));
        }

        if let Some(from_cursor) = &self.from_cursor {
            command.push_str(&format!(" --after-cursor='{from_cursor}'"));
        }

        let mut grep = "grep --extended-regexp".to_string();
        if !self.grep_flags.is_empty() {
            grep.push(' ');
            grep.push_str(&Vec::from_iter(self.grep_flags.iter().cloned()).join(" "));
        }
        command.push_str(&format!(" | {grep} '{search_regex}'"));

        let output =
            execute_bash_command(&self.session, command).map_err(|e| anyhow::anyhow!(e))?;
        Ok(output
            .lines()
            .map(|line| {
                let output: JournalOutput =
                    serde_json::from_str(line).expect("Journal output should be valid JSON");
                (output.message, output.cursor)
            })
            .collect::<Vec<_>>())
    }
}
