use std::collections::BTreeSet;

use crate::ssh_access::execute_bash_command;
use serde::{Deserialize, Serialize};
use ssh2::Session;

pub struct JournalStreamer {
    session: Session,
    journalctl_flags: BTreeSet<String>,
    from_cursor: Option<String>,
    to_cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct JournalOutput {
    #[serde(alias = "MESSAGE")]
    message: String,
    #[serde(alias = "__CURSOR")]
    cursor: String,
}

impl JournalStreamer {
    pub fn new(session: Session) -> Self {
        Self {
            session,
            journalctl_flags: BTreeSet::new(),
            from_cursor: None,
            to_cursor: None,
        }
    }

    pub fn max_lines(mut self, max_lines: usize) -> Self {
        self.journalctl_flags.insert(format!("-n{}", max_lines));
        self
    }

    pub fn follow(mut self) -> Self {
        self.journalctl_flags.insert("-f".to_string());
        self
    }

    pub fn from_now(self) -> Self {
        let (_message, cursor) = Self::new(self.session.clone())
            .max_lines(1)
            .search_and_return_cursors("__CURSOR")?
            .into_iter()
            .next()
            .expect("The journal should have at least one entry");

        self.from_cursor = Some(cursor.to_string());
        self
    }

    pub fn until(mut self, search_regex: &str) -> anyhow::Result<Self> {
        let (_message, cursor) = self
            .search_and_return_cursors(search_regex)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("No journal entries found matching the regex '{search_regex}'")
            })?;

        self.to_cursor = Some(cursor.to_string());
        self
    }

    pub fn search(&self, search_regex: &str) -> anyhow::Result<Vec<String>> {
        self.search_and_return_cursors(search_regex)
            .map(|iter| iter.into_iter().map(|(message, _cursor)| message).collect())
    }

    fn search_and_return_cursors(
        &self,
        search_regex: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
        assert!(
            self.from_cursor.is_none() || self.to_cursor.is_none(),
            "Cannot specify both from and to cursors"
        );

        let mut command = "journalctl -o json --output-fields='MESSAGE,__CURSOR'".to_string();

        if !self.journalctl_flags.is_empty() {
            command.push(' ');
            command.push_str(&Vec::from_iter(self.journalctl_flags.iter().cloned()).join(" "));
        }

        if let Some(from_cursor) = &self.from_cursor {
            command.push_str(&format!(" --after-cursor='{}'", from_cursor));
        }

        if let Some(to_cursor) = &self.to_cursor {
            command.push_str(&format!(" --cursor='{}' --reverse", to_cursor));
        }

        command.push_str(&format!(" | grep -E '{}'", search_regex));

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
