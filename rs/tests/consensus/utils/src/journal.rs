use crate::ssh_access::execute_bash_command;
use serde::{Deserialize, Serialize};
use ssh2::Session;

#[derive(Debug, Deserialize, Serialize)]
pub struct Cursor {
    #[serde(alias = "__CURSOR")]
    pub cursor: String,
}

pub fn fetch_journal_cursor(session: &Session) -> anyhow::Result<Cursor> {
    let cursor_str = execute_bash_command(
        &session,
        "journalctl -n1 -o json --output-fields='__CURSOR'".to_string(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    Ok(serde_json::from_str(&cursor_str).expect("Journal cursor should be valid JSON"))
}

pub fn find_journal_matches_after_cursor(
    session: &Session,
    cursor: &Cursor,
    search_string: &str,
) -> anyhow::Result<Vec<String>> {
    run_journalctl_command(
        session,
        format!(
            "journalctl --after-cursor='{}' | grep -E '{}'",
            cursor.cursor, search_string
        ),
    )
}

pub fn find_journal_matches(session: &Session, search_string: &str) -> anyhow::Result<Vec<String>> {
    run_journalctl_command(session, format!("journalctl | grep -E '{}'", search_string))
}

pub fn stream_journal_for_matches(
    session: &Session,
    search_string: &str,
) -> anyhow::Result<Vec<String>> {
    run_journalctl_command(
        session,
        format!("journalctl -f | grep -E '{}'", search_string),
    )
}

fn run_journalctl_command(session: &Session, command: String) -> anyhow::Result<Vec<String>> {
    let output = execute_bash_command(session, command).map_err(|e| anyhow::anyhow!(e))?;
    Ok(output.lines().map(|line| line.to_string()).collect())
}
