use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;

/// Size of each bucket in the lookup table.
const BUCKET_SIZE: usize = PAGE_SIZE;
const _: () = assert!(BUCKET_SIZE >= PAGE_SIZE); // Should not be lower than 4 KiB OS page size.

/// Represents a single entry in the ring buffer's lookup table.
///
/// Each entry maps a fixed-size bucket in the data region
/// to the most recent log record within that bucket.
#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) struct LookupEntry {
    /// Index of the log record.
    pub idx: u64,
    /// Timestamp of the log record.
    pub ts_nanos: u64,
    /// Position of the log record in the ring buffer's data region.
    pub position: MemoryPosition,
}
pub(crate) const LOOKUP_ENTRY_SIZE: usize = 24;
const _: () = assert!(std::mem::size_of::<LookupEntry>() == LOOKUP_ENTRY_SIZE);

impl LookupEntry {
    const INVALID_ENTRY: u64 = u64::MAX;

    pub fn new(record: &LogRecord, position: MemoryPosition) -> Self {
        Self {
            idx: record.idx,
            ts_nanos: record.ts_nanos,
            position,
        }
    }

    fn invalid() -> Self {
        Self {
            idx: Self::INVALID_ENTRY,
            ts_nanos: 0,
            position: MemoryPosition::new(0),
        }
    }

    fn is_valid(&self) -> bool {
        self.idx != Self::INVALID_ENTRY
    }

    fn write(&self, writer: &mut ByteWriter) {
        writer.write_u64(self.idx);
        writer.write_u64(self.ts_nanos);
        writer.write_u64(self.position.get());
    }

    /// Returns the bucket index for this entry's position.
    fn bucket_index(&self) -> usize {
        (self.position.get() as usize) / BUCKET_SIZE
    }
}

/// A lookup table for efficiently locating log records in the ring buffer.
///
/// The table divides the ring buffer's data region into fixed-size buckets.
/// Each bucket stores the latest log record that was written within its range.
/// The table also tracks the oldest available log record to define the valid range.
///
/// This allows fast determination of positions for reading logs matching a filter,
/// without scanning the entire data region.
#[derive(Debug, PartialEq)]
pub(crate) struct LookupTable {
    /// The oldest available log record in the ring buffer.
    ///
    /// Used to determine which buckets are currently valid.
    front: Option<LookupEntry>,

    /// Array of buckets, each storing the latest known log record for that data segment.
    ///
    /// The bucket index is calculated from the log record's position in the data region.
    /// Updating this table happens when a new record is written, replacing or appending
    /// entries for the corresponding bucket.
    buckets: Vec<LookupEntry>,
}

impl LookupTable {
    pub fn new(
        front: Option<LookupEntry>,
        lookup_table_pages: u16,
        data_capacity: MemorySize,
        bytes: &[u8],
    ) -> Self {
        let max_count = (lookup_table_pages as usize * PAGE_SIZE) / BUCKET_SIZE;
        let count = ((data_capacity.get() as usize) / BUCKET_SIZE).min(max_count);
        let buckets = if bytes.is_empty() {
            vec![LookupEntry::invalid(); count]
        } else {
            to_entries(bytes)
        };
        Self { front, buckets }
    }

    pub fn buckets_len(&self) -> u16 {
        self.buckets.len() as u16
    }

    pub fn serialized_buckets(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.buckets.len() * LOOKUP_ENTRY_SIZE];
        let mut writer = ByteWriter::new(&mut bytes);
        self.buckets.iter().for_each(|e| e.write(&mut writer));
        bytes
    }

    /// Updates or appends a lookup entry for the given log record at the specified position.
    pub fn update_last(&mut self, record: &LogRecord, position: MemoryPosition) {
        let entry = LookupEntry::new(record, position);
        let index = entry.bucket_index();
        if index < self.buckets.len() {
            self.buckets[index] = entry;
        }
    }

    fn get_sorted_valid_entries(&self) -> Vec<LookupEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid buckets.
        let mut valid_entries: Vec<LookupEntry> = self
            .buckets
            .iter()
            .filter(|e| e.is_valid() && front.idx < e.idx)
            .cloned()
            .collect();
        valid_entries.push(front);
        valid_entries.sort_by_key(|e| e.idx);
        valid_entries
    }

    /// Function returns a range [start, end) of positions in the data region.
    pub fn get_range(
        &self,
        filter: &Option<FetchCanisterLogsFilter>,
    ) -> Option<(MemoryPosition, MemoryPosition)> {
        const MAX_RANGE_SIZE: MemorySize = MemorySize::new(2_000_000); // 2 MB

        let entries = self.get_sorted_valid_entries();
        if entries.is_empty() {
            return None;
        }

        // Left fallback for start: exact match or previous entry.
        let find_start_by_key = |key: u64, key_fn: fn(&LookupEntry) -> u64| -> MemoryPosition {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx].position,      // Exact match.
                Err(0) => entries[0].position,         // Below range, return first.
                Err(idx) => entries[idx - 1].position, // Left fallback.
            }
        };

        // Right fallback for end: exact match or next entry.
        let find_end_by_key = |key: u64, key_fn: fn(&LookupEntry) -> u64| -> MemoryPosition {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx].position, // Exact match.
                Err(idx) if idx < entries.len() => entries[idx].position, // Right fallback.
                _ => entries.last().unwrap().position, // Above range, return last.
            }
        };

        // Clamp `end` so `end - start <= MAX_RANGE_SIZE`.
        let clamp_to_max_range = |start: MemoryPosition, end: MemoryPosition| -> MemoryPosition {
            let max_allowed_end = start + MAX_RANGE_SIZE;
            if max_allowed_end < end {
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
                let min_allowed_start = end.saturating_sub(MAX_RANGE_SIZE);
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
            return Some((start, end + MemorySize::new(BUCKET_SIZE as u64)));
        }
        Some((start, end))
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
