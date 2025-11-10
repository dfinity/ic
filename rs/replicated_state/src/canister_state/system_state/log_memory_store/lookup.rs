use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;
use std::convert::From;

/// Size of each bucket in the lookup table.
const BUCKET_SIZE: usize = PAGE_SIZE;
const _: () = assert!(BUCKET_SIZE >= PAGE_SIZE); // Should not be lower than 4 KiB OS page size.

/// A compact index mapping fixed-size buckets of the data region
/// to their latest known log record within each bucket.
///
/// Each bucket covers `BUCKET_SIZE` bytes. When a new record is written, the
/// corresponding bucket entry is updated with its latest log record lookup entry.
///
/// The table also stores `front` — the oldest available record in the ring
/// buffer — to define the lower bound of the valid record range.
#[derive(Debug, PartialEq)]
pub(crate) struct LookupTable {
    /// One entry per bucket — holds the latest log record lookup entry.
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

    fn get_valid_entries(&self) -> Vec<LookupEntry> {
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

    // Function returns a range [start, end) of memory positions.
    pub fn get_range(
        &self,
        filter: &Option<FetchCanisterLogsFilter>,
    ) -> (MemoryPosition, MemoryPosition) {
        const MAX_RANGE_BYTES: MemorySize = MemorySize::new(2_000_000); // 2 MB

        let entries = self.get_valid_entries();
        if entries.is_empty() {
            return (MemoryPosition::new(0), MemoryPosition::new(0));
        }

        // Left fallback for start: exact match or previous entry.
        let find_start_by_key = |key: u64, key_fn: fn(&LookupEntry) -> u64| -> MemoryPosition {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx].position,      // Exact match.
                Err(0) => entries[0].position,         // Outside range, return first.
                Err(idx) => entries[idx - 1].position, // Left fallback.
            }
        };

        // Right fallback for end: exact match or next entry.
        let find_end_by_key = |key: u64, key_fn: fn(&LookupEntry) -> u64| -> MemoryPosition {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx].position, // Exact match.
                Err(idx) if idx < entries.len() => entries[idx].position, // Right fallback.
                _ => entries.last().unwrap().position, // Outside range, return last.
            }
        };

        // Clamp `end` so (end - start) <= MAX_RANGE_BYTES.
        let clamp_to_max_range = |start: MemoryPosition, end: MemoryPosition| -> MemoryPosition {
            let max_allowed_end = start + MAX_RANGE_BYTES;
            if end > max_allowed_end {
                find_end_by_key(max_allowed_end.get(), |e| e.position.get())
            } else {
                end
            }
        };

        let (start, end) = match filter {
            None => {
                // Return latest range limited by MAX_RANGE_BYTES.
                // Use left fallback for start to avoid dropping earlier valid data.
                let end = entries.last().unwrap().position;
                let min_allowed_start = end.saturating_sub(MAX_RANGE_BYTES);
                let start = find_start_by_key(min_allowed_start.get(), |e| e.position.get());
                (start, end)
            }
            Some(FetchCanisterLogsFilter::ByIdx(range)) => {
                let start = find_start_by_key(range.start, |e| e.idx);
                let end = find_end_by_key(range.end, |e| e.idx);
                (start, clamp_to_max_range(start, end))
            }
            Some(FetchCanisterLogsFilter::ByTimestampNanos(range)) => {
                let start = find_start_by_key(range.start, |e| e.ts_nanos);
                let end = find_end_by_key(range.end, |e| e.ts_nanos);
                (start, clamp_to_max_range(start, end))
            }
        };
        // If start == end they point to the same bucket which can have records,
        // so we need to adjust end to the next bucket.
        if start == end {
            // TODO: handle case when buffer is full and they are pointing to the same bucket.
            return (start, end + MemorySize::new(BUCKET_SIZE as u64));
        }
        (start, end)
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
