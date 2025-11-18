use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
    ring_buffer::{INDEX_ENTRY_SIZE, RESULT_MAX_SIZE},
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;

/// Sentinel value for invalid index entries.
const INVALID_INDEX_ENTRY: u64 = u64::MAX;

/// Lightweight pointer to a single log record used by the index table.
/// Holds the record `idx` (unique increasing id), its `timestamp` and the
/// `position` inside the data region where the record header begins.
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub idx: u64,
    pub timestamp: u64,
    pub position: MemoryPosition,
}
const _: () = assert!(std::mem::size_of::<IndexEntry>() == INDEX_ENTRY_SIZE.get() as usize);

impl IndexEntry {
    /// Creates an `IndexEntry` pointing to `position` for `record`.
    pub fn new(position: MemoryPosition, record: &LogRecord) -> Self {
        Self {
            idx: record.idx,
            timestamp: record.timestamp,
            position,
        }
    }

    /// Creates an explicitly invalid entry, used to initialize empty slots.
    fn invalid() -> Self {
        Self {
            idx: INVALID_INDEX_ENTRY,
            timestamp: INVALID_INDEX_ENTRY,
            position: MemoryPosition::new(INVALID_INDEX_ENTRY),
        }
    }

    /// True when this entry contains a valid pointer to a record.
    fn is_valid(&self) -> bool {
        self.idx != INVALID_INDEX_ENTRY
    }
}

/// Index table used to speed up searches in the log’s data region.
///
/// The data region is a large ring buffer that stores log records. Because only
/// the head and tail positions are known, scanning the buffer to locate a
/// specific record would normally require reading many records sequentially.
///
/// The index table solves this by dividing the data region into fixed-size
/// segments. Each segment has an `IndexEntry` pointing to the most recent record
/// written in that segment. The table also tracks the position of the oldest
/// live record (`front`).
///
/// Together, these entries let the system quickly determine which parts of the
/// ring buffer may contain records of interest, reducing the amount of data
/// that must be read during large or targeted searches.
#[derive(Debug)]
pub struct IndexTable {
    pub front: Option<IndexEntry>, // Position of the oldest live log record.
    pub entries: Vec<IndexEntry>,  // Array of entries covering all data region segments.
    pub segment_size: MemorySize,  // Size of each data region segment in bytes.
    pub data_capacity: MemorySize, // Total capacity of the data region.
}

impl IndexTable {
    /// Creates a table that partitions the data region into fixed-size segments.
    /// If no entries are provided, all segments start out invalid.
    pub fn new(
        front: Option<IndexEntry>, // front might be empty if there are no log records yet.
        data_capacity: MemorySize,
        index_table_pages: u16,
        entries: Vec<IndexEntry>,
    ) -> Self {
        let total_size_max = index_table_pages as usize * PAGE_SIZE;
        let entry_size = INDEX_ENTRY_SIZE.get() as usize;
        debug_assert!(entry_size > 0);
        let entries_count = total_size_max / entry_size;
        debug_assert!(entries_count > 0);
        let segment_size = data_capacity.get() as usize / entries_count;
        debug_assert!(entries_count * entry_size <= total_size_max);

        let entries = if entries.is_empty() {
            vec![IndexEntry::invalid(); entries_count]
        } else {
            entries
        };
        Self {
            front,
            entries,
            segment_size: MemorySize::new(segment_size as u64),
            data_capacity,
        }
    }

    /// Records the most recent log entry associated with the segment that contains `position`.
    ///
    /// This operation assumes that log records arrive strictly in increasing `idx` order —
    /// meaning each update corresponds to a newer record than any previously stored one.
    /// Because segments keep only the newest record, providing an out-of-order record would
    /// silently overwrite newer data and corrupt segment ordering.
    ///
    /// IMPORTANT: callers must guarantee monotonic `idx` progression.
    pub fn update(&mut self, position: MemoryPosition, record: &LogRecord) {
        if let Some(index) = self.segment_index(position) {
            self.entries[index] = IndexEntry::new(position, record);
        }
    }

    /// Map a data-region position to its segment index, or return `None` if
    /// the position falls outside the table’s layout.
    fn segment_index(&self, position: MemoryPosition) -> Option<usize> {
        let segment_size = self.segment_size.get();
        if segment_size == 0 {
            return None;
        }
        let idx = (position.get() / segment_size) as usize;
        (idx < self.entries.len()).then_some(idx)
    }

    /// Return all valid entries at or after `front`, sorted by increasing idx.
    /// Used to narrow down searches without scanning the entire region.
    pub fn valid_sorted_entries(&self) -> Vec<IndexEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid buckets.
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.is_valid() && front.idx < e.idx)
            .cloned()
            .collect();
        entries.push(front);
        entries.sort_by_key(|e| e.idx);
        entries.dedup_by_key(|e| e.idx);
        entries
    }

    /// Compute a coarse `[start, end]` inclusive entry range that bounds the query
    /// described by `filter`, minimizing how much of the ring must be scanned.
    pub fn get_coarse_range(
        &self,
        filter: Option<FetchCanisterLogsFilter>,
    ) -> Option<(IndexEntry, IndexEntry)> {
        let entries = self.valid_sorted_entries();
        if entries.is_empty() {
            return None;
        }

        if entries.len() == 1 {
            // Only one valid entry means only one record (the front) is in the buffer.
            return Some((entries[0], entries[0]));
        }

        // Below this line there's always at least 2 unique entries covering the full valid range
        // from the oldest to the latest log record.

        // Left fallback for start: exact match or previous entry.
        let find_start_by_key = |key: u64, key_fn: fn(&IndexEntry) -> u64| -> IndexEntry {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx],      // Exact match.
                Err(0) => entries[0],         // Below range, return first.
                Err(idx) => entries[idx - 1], // Left fallback.
            }
        };

        // Right fallback for end: exact match or next entry.
        let find_end_by_key = |key: u64, key_fn: fn(&IndexEntry) -> u64| -> IndexEntry {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx],                         // Exact match.
                Err(idx) if idx < entries.len() => entries[idx], // Right fallback.
                _ => *entries.last().unwrap(),                   // Above range, return last.
            }
        };

        let filter_by_idx =
            |entries: &Vec<IndexEntry>, start_idx: u64, end_idx: u64| -> Vec<IndexEntry> {
                entries
                    .iter()
                    .filter(|e| start_idx <= e.idx && e.idx <= end_idx)
                    .cloned()
                    .collect()
            };

        let clamp_end_by_size = |entries: &Vec<IndexEntry>, size_limit: MemorySize| -> IndexEntry {
            let start_position = entries.first().unwrap().position;
            for entry in entries {
                if self.distance(start_position, entry.position) >= size_limit {
                    return *entry;
                }
            }
            *entries.last().unwrap()
        };

        let size_limit = RESULT_MAX_SIZE + self.segment_size;
        let (start, end) = match filter {
            Some(FetchCanisterLogsFilter::ByIdx(range)) => {
                let start = find_start_by_key(range.start, |e| e.idx);
                let end = find_end_by_key(range.end, |e| e.idx);
                let subset = filter_by_idx(&entries, start.idx, end.idx);
                if subset.is_empty() {
                    (start, end)
                } else {
                    (start, clamp_end_by_size(&subset, size_limit))
                }
            }
            Some(FetchCanisterLogsFilter::ByTimestampNanos(range)) => {
                let start = find_start_by_key(range.start, |e| e.timestamp);
                let end = find_end_by_key(range.end, |e| e.timestamp);
                let subset = filter_by_idx(&entries, start.idx, end.idx);
                if subset.is_empty() {
                    (start, end)
                } else {
                    (start, clamp_end_by_size(&subset, size_limit))
                }
            }
            None => {
                let mut start = entries.first().unwrap();
                let end = entries.last().unwrap();
                for entry in entries.iter().rev() {
                    start = entry;
                    if self.distance(entry.position, end.position) >= size_limit {
                        break;
                    }
                }
                (*start, *end)
            }
        };

        Some((start, end))
    }

    /// Calculates forward distance between two positions in the ring, handles wraparound.
    fn distance(&self, from: MemoryPosition, to: MemoryPosition) -> MemorySize {
        if to >= from {
            to - from // no wrap
        } else {
            debug_assert!(self.data_capacity.get() > 0);
            (self.data_capacity + to) - from // wrap
        }
    }
}

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=get_range_returns_valid_range_when_records_provided
*/
