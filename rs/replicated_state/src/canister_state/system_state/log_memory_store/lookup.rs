#![allow(dead_code)] // TODO: don't forget to cleanup.

use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;

/// Maximum data capacity of the ring buffer.
const MAX_DATA_CAPACITY: MemorySize = MemorySize::new(2 * 1024 * 1024); // 2 MiB

/// Maximum allowed fetch logs response size.
const MAX_FETCH_LOGS_RESPONSE_SIZE: MemorySize = MemorySize::new(2_000_000); // 2 MB
const _: () = assert!(MAX_FETCH_LOGS_RESPONSE_SIZE.get() <= 2_000_000); // Must not exceed 2 MB, message size limit.

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

    /// Total capacity of the data region in memory.
    data_capacity: MemorySize,

    /// Size of each bucket in data region.
    bucket_size: MemorySize,
}

impl LookupTable {
    pub fn new(
        front: Option<LookupEntry>,
        lookup_table_pages: u16,
        data_capacity: MemorySize,
        bytes: &[u8],
    ) -> Self {
        assert!(data_capacity <= MAX_DATA_CAPACITY);

        let lookup_table_size = lookup_table_pages as usize * PAGE_SIZE;
        let buckets_count = lookup_table_size / LOOKUP_ENTRY_SIZE;
        let bucket_size = if buckets_count > 0 {
            MemorySize::new(data_capacity.get() / buckets_count as u64)
        } else {
            MemorySize::new(0)
        };
        debug_assert!(
            bucket_size.get() * buckets_count as u64 <= data_capacity.get(),
            "Total buckets size must not exceed data capacity",
        );

        let buckets = if bytes.is_empty() {
            vec![LookupEntry::invalid(); buckets_count]
        } else {
            to_entries(bytes)
        };
        Self {
            front,
            buckets,
            data_capacity,
            bucket_size,
        }
    }

    pub fn buckets_len(&self) -> u16 {
        self.buckets.len() as u16
    }

    /// Returns the bucket index for this entry's position.
    fn bucket_index(&self, position: MemoryPosition) -> usize {
        (position.get() as usize) / self.bucket_size.as_usize()
    }

    pub fn serialized_buckets(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.buckets.len() * LOOKUP_ENTRY_SIZE];
        let mut writer = ByteWriter::new(&mut bytes);
        self.buckets.iter().for_each(|e| e.write(&mut writer));
        bytes
    }

    /// Updates or appends a lookup entry for the given log record at the specified position.
    pub fn update_last(&mut self, record: &LogRecord, position: MemoryPosition) {
        let index = self.bucket_index(position);
        if index < self.buckets.len() {
            self.buckets[index] = LookupEntry::new(record, position);
        }
    }

    /// Returns all valid lookup entries since the front entry (included), sorted by index.
    fn valid_entries_since_front(&self) -> Vec<LookupEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid buckets.
        let mut entries: Vec<LookupEntry> = self
            .buckets
            .iter()
            .filter(|e| e.is_valid() && front.idx < e.idx)
            .cloned()
            .collect();
        entries.push(front);
        entries.sort_by_key(|e| e.idx);
        entries.dedup_by_key(|e| e.idx);
        entries
    }

    /// Function returns a range [start, end) of positions in the data region.
    pub fn get_range(
        &self,
        filter: &Option<FetchCanisterLogsFilter>,
    ) -> Option<(MemoryPosition, MemoryPosition)> {
        const END_OFFSET: MemorySize = MemorySize::new(1);

        let entries = self.valid_entries_since_front();
        if entries.is_empty() {
            return None;
        }

        if entries.len() == 1 {
            // Only one valid entry means only one record (the front) is in the buffer,
            // so return its position as a range of size 1.
            let start = entries[0].position;
            return Some((start, start + END_OFFSET));
        }

        // Below this line there's always at least 2 unique entries covering the full valid range
        // from the oldest to the latest log record.

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

        // Clamp `end` so `end - start <= MAX_FETCH_LOGS_RESPONSE_SIZE`.
        let clamp_to_max_range = |start: MemoryPosition, end: MemoryPosition| -> MemoryPosition {
            let max_allowed_end = start + MAX_FETCH_LOGS_RESPONSE_SIZE;
            if max_allowed_end < end {
                // TODO: fix this.
                find_end_by_key(max_allowed_end.get(), |e| e.position.get())
            } else {
                end
            }
        };

        let (start, end) = match filter {
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
            None => {
                // Return latest range limited by MAX_RANGE_BYTES.
                // Find the earliest entry whose distance to the last entry is >= MAX_FETCH_LOGS_RESPONSE_SIZE.
                debug_assert!(
                    MAX_FETCH_LOGS_RESPONSE_SIZE > MemorySize::new(2 * self.bucket_size.get()),
                    "MAX_FETCH_LOGS_RESPONSE_SIZE must be larger than 2 * BUCKET_SIZE to ensure at least 2 entries can fit in the range"
                );

                let idx = lower_bound_by_min_distance(
                    &entries,
                    self.data_capacity,
                    MAX_FETCH_LOGS_RESPONSE_SIZE,
                );
                // Since MAX_FETCH_LOGS_RESPONSE_SIZE > 2 * BUCKET_SIZE, start and end will always differ.
                let start = if idx < entries.len() {
                    entries[idx].position
                } else {
                    // No entry satisfies the distance — fall back to the earliest entry
                    entries[0].position
                };

                let end = entries.last().unwrap().position;
                (start, end)
            }
        };
        // Since we have at least 2 unique entries, start and end will never be the same.
        debug_assert!(start != end, "start and end positions must differ");

        Some((start, end + END_OFFSET))
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

/// Find the smallest index `i` such that the forward distance from `entries[i].position`
/// to `end` is **at least** `min_distance` — i.e., the first `i` where
/// `dist_to_end(entries[i].position) >= min_distance`.
///
/// Returns `entries.len()` if no such index exists.
pub(crate) fn lower_bound_by_min_distance(
    entries: &[LookupEntry],
    data_capacity: MemorySize,
    min_distance: MemorySize,
) -> usize {
    if entries.is_empty() {
        return 0;
    }
    let end = entries.last().unwrap().position;

    // forward distance from `pos` to `end`, accounting for wrap-around
    let dist_to_end = |pos: MemoryPosition| -> MemorySize {
        if end >= pos {
            end - pos // no wrap-around
        } else {
            (data_capacity + end) - pos // wrap-around
        }
    };

    // classic lower_bound: find smallest i such that dist_to_end(entries[i].position) >= min_distance
    let mut lo = 0;
    let mut hi = entries.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if dist_to_end(entries[mid].position) >= min_distance {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA_CAPACITY: MemorySize = MemorySize::new(2_000_000); // 2 MB

    fn lookup_entry(idx: u64, ts_nanos: u64, position: MemoryPosition) -> LookupEntry {
        LookupEntry {
            idx,
            ts_nanos,
            position,
        }
    }

    fn fake_record(entry: &LookupEntry) -> LogRecord {
        LogRecord {
            idx: entry.idx,
            ts_nanos: entry.ts_nanos,
            len: 0,          // length is not relevant for this test
            content: vec![], // content is not relevant for this test
        }
    }

    fn make_entries(
        count: u64,
        start_position: MemoryPosition,
        record_size: MemorySize,
    ) -> Vec<LookupEntry> {
        (0..count)
            .map(|i| {
                lookup_entry(
                    i,
                    1_000_000 + i * 1_000, // arbitrary timestamp
                    start_position + MemorySize::new(i * record_size.get()),
                )
            })
            .collect()
    }

    fn setup(
        records_count: u64,
        start_position: MemoryPosition,
        record_size: MemorySize,
        data_capacity: MemorySize,
    ) -> (Vec<LookupEntry>, LookupTable) {
        let entries = make_entries(records_count, start_position, record_size);
        let front = if entries.is_empty() {
            None
        } else {
            Some(entries[0])
        };
        let mut table = LookupTable::new(front, 1, data_capacity, &[]);
        for entry in &entries {
            table.update_last(&fake_record(entry), entry.position);
        }
        (entries, table)
    }

    #[test]
    fn get_range_returns_none_when_no_records_provided() {
        let data_capacity = TEST_DATA_CAPACITY;
        let start_position = MemoryPosition::new(0);
        let records_count = 0;
        let record_size = MemorySize::new(0);

        let (entries, table) = setup(records_count, start_position, record_size, data_capacity);
        let range = table.get_range(&None);

        assert!(entries.is_empty(), "expected no entries to be created");
        assert!(range.is_none(), "expected None when no entries are present");
    }

    #[test]
    fn get_range_returns_valid_range_when_records_provided() {
        let data_capacity = TEST_DATA_CAPACITY;
        let start_position = MemoryPosition::new(0);
        let record_size = MemorySize::new(1_000);
        let max_count = 1_000;
        assert!(max_count * record_size.get() < MAX_FETCH_LOGS_RESPONSE_SIZE.get());

        for records_count in 1..max_count {
            let (entries, table) = setup(records_count, start_position, record_size, data_capacity);
            let (start, end) = table
                .get_range(&None)
                .expect("Expected a range to be returned");

            assert_eq!(start, entries[0].position);
            assert!(entries.last().unwrap().position < end);
        }
    }
}

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=get_range_returns_valid_range_when_records_provided
*/
