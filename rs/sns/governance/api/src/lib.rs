use pb::v1::UpgradeJournal;

pub mod pb;
mod types;

/// Formats the 32 bytes of a hash as a hexadecimal string. Corresponds to 64 ascii symbols.
pub fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Formats `journal.entries` as JSON.
pub fn serialize_journal_entries(journal: &UpgradeJournal) -> Result<String, String> {
    serde_json::to_string(&journal.entries).map_err(|err| format!("{err:?}"))
}
