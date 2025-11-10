use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord, memory::MemoryPosition,
};
use std::convert::From;

const BUCKET_SIZE: usize = 4 * 1024; // 4 KiB per bucket.

/// `LookupTable` — compact index mapping fixed-size buckets of the data region
/// to their latest known log record within each bucket.
///
/// Each bucket covers `BUCKET_SIZE` bytes. When a new record is written, the
/// corresponding bucket entry is updated with its `{idx, ts_nanos, position}`.
///
/// The table also stores `front` — the oldest available record in the ring
/// buffer — to define the lower bound of the valid record range.
#[derive(Debug, PartialEq)]
pub(crate) struct LookupTable {
    /// One entry per bucket — holds the latest `{idx, ts_nanos, position}`.
    entries: Vec<LookupEntry>,

    /// The oldest available record (front) in the ring buffer.
    front: Option<LookupEntry>,
}

impl LookupTable {
    pub fn new(entries: Vec<LookupEntry>) -> Self {
        Self {
            entries,
            front: None,
        }
    }

    pub fn set_front(&mut self, entry: Option<LookupEntry>) {
        self.front = entry;
    }

    pub fn get_valid_entries(&self) -> Vec<LookupEntry> {
        let front = match self.front {
            Some(entry) => entry,
            None => return vec![],
        };
        let mut valid_entries: Vec<LookupEntry> = self
            .entries
            .iter()
            .filter(|e| front.idx < e.idx)
            .cloned()
            .collect();
        valid_entries.push(front);
        valid_entries.sort_by_key(|e| e.idx);
        valid_entries
    }

    /// Updates or appends a lookup entry for the given log record at the specified position.
    pub fn update_last(&mut self, record: &LogRecord, position: MemoryPosition) {
        let entry = LookupEntry {
            idx: record.idx,
            ts_nanos: record.ts_nanos,
            position,
        };
        let index = self.bucket_index_of(position);
        if index < self.entries.len() {
            self.entries[index] = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Calculates bucket index for a given memory position.
    fn bucket_index_of(&self, position: MemoryPosition) -> usize {
        (position.get() as usize) / BUCKET_SIZE
    }
}

pub(crate) fn to_entries(bytes: &[u8]) -> Vec<LookupEntry> {
    // Each entry is a fixed-size record; anything else is a bug.
    debug_assert_eq!(
        bytes.len() % LOOKUP_ENTRY_SIZE,
        0,
        "lookup table bytes must be a multiple of LOOKUP_ENTRY_SIZE",
    );

    let entry_count = bytes.len() / LOOKUP_ENTRY_SIZE;
    let mut reader = ByteReader::new(bytes);
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        entries.push(LookupEntry {
            idx: reader.read_u64(),
            ts_nanos: reader.read_u64(),
            position: MemoryPosition::new(reader.read_u64()),
        });
    }

    entries
}

impl From<&LookupTable> for Vec<u8> {
    fn from(table: &LookupTable) -> Self {
        let mut bytes = vec![0; table.entries.len() * LOOKUP_ENTRY_SIZE];
        let mut writer = ByteWriter::new(&mut bytes);

        for entry in &table.entries {
            writer.write_u64(entry.idx);
            writer.write_u64(entry.ts_nanos);
            writer.write_u64(entry.position.get());
        }

        bytes
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) struct LookupEntry {
    pub idx: u64,
    pub ts_nanos: u64,
    pub position: MemoryPosition,
}
pub(crate) const LOOKUP_ENTRY_SIZE: usize = 24;
const _: () = assert!(std::mem::size_of::<LookupEntry>() == LOOKUP_ENTRY_SIZE);
