use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
    ring_buffer::{INDEX_ENTRY_SIZE, RESULT_MAX_SIZE},
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;

const INVALID_INDEX_ENTRY: u64 = u64::MAX;

/// A single index entry representing a segment in the data region.
/// Stores the position of the newest log record in its segment.
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub idx: u64,                 // Incremental ID of the record.
    pub timestamp: u64,           // Timestamp in nanoseconds.
    pub position: MemoryPosition, // Offset in the data region of the newest record.
}

// TODO: assert IndexEntry size.

impl IndexEntry {
    pub fn new(position: MemoryPosition, record: &LogRecord) -> Self {
        Self {
            idx: record.idx,
            timestamp: record.timestamp,
            position,
        }
    }

    fn invalid() -> Self {
        Self {
            idx: INVALID_INDEX_ENTRY,
            timestamp: INVALID_INDEX_ENTRY,
            position: MemoryPosition::new(INVALID_INDEX_ENTRY),
        }
    }

    fn is_valid(&self) -> bool {
        self.idx != INVALID_INDEX_ENTRY
    }
}

/// Index table structure mapping segments of the data region to IndexEntry elements.
#[derive(Debug)]
pub struct IndexTable {
    pub front: Option<IndexEntry>, // Position of the oldest live record.
    pub entries: Vec<IndexEntry>,  // Array of entries covering all segments.
    pub segment_size: MemorySize,  // Size of each segment in bytes.
    pub data_capacity: MemorySize, // Total capacity of the data region.
}

impl IndexTable {
    /// Creates a new IndexTable with all entries invalid and segment size calculated.
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

    /// Updates the last record in the corresponding segment.
    pub fn update(&mut self, position: MemoryPosition, record: &LogRecord) {
        if let Some(index) = self.segment_index(position) {
            self.entries[index] = IndexEntry::new(position, record);
        }
    }

    fn segment_index(&self, position: MemoryPosition) -> Option<usize> {
        let segment_size = self.segment_size.get();
        if segment_size == 0 {
            return None;
        }
        let idx = (position.get() / segment_size) as usize;
        (idx < self.entries.len()).then_some(idx)
    }

    /// Returns a vector of valid entries sorted by idx for coarse searching.
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

    /// Returns the coarse range of index entries [start, end] for the given filter.
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
                (start, clamp_end_by_size(&subset, size_limit))
            }
            Some(FetchCanisterLogsFilter::ByTimestampNanos(range)) => {
                let start = find_start_by_key(range.start, |e| e.timestamp);
                let end = find_end_by_key(range.end, |e| e.timestamp);
                let subset = filter_by_idx(&entries, start.idx, end.idx);
                (start, clamp_end_by_size(&subset, size_limit))
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

    /// Calculates the distance between two memory positions in the ring buffer.
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
