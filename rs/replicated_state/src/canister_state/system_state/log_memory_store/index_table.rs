use crate::canister_state::system_state::log_memory_store::{
    log_record::LogRecord,
    memory::{MemoryPosition, MemorySize},
    ring_buffer::INDEX_ENTRY_SIZE,
};
use crate::page_map::PAGE_SIZE;
use ic_management_canister_types_private::FetchCanisterLogsFilter;

/// Sentinel value for invalid index entries.
const INVALID_INDEX_ENTRY: u64 = u64::MAX;

/// Lightweight descriptor of a single log record used by the index table.
/// It stores the record’s start position in the data region and basic
/// metadata for range queries (idx, timestamp, byte length).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct IndexEntry {
    /// Start position of the record within the data region.
    pub position: MemoryPosition,
    /// Record unituque sequential index.
    pub idx: u64,
    /// Record timestamp.
    pub timestamp: u64,
    /// Record total byte length.
    pub bytes_len: u32,
}
const _: () = assert!(INDEX_ENTRY_SIZE.get() as usize == 8 + 8 + 8 + 4);

impl IndexEntry {
    /// Creates an entry for a record at the given position with its indexing metadata.
    pub fn new(position: MemoryPosition, record: &LogRecord) -> Self {
        Self {
            position,
            idx: record.idx,
            timestamp: record.timestamp,
            bytes_len: record.bytes_len() as u32,
        }
    }

    /// Creates an explicitly invalid entry, used to initialize empty slots.
    fn invalid() -> Self {
        Self {
            position: MemoryPosition::new(INVALID_INDEX_ENTRY),
            idx: INVALID_INDEX_ENTRY,
            timestamp: INVALID_INDEX_ENTRY,
            bytes_len: 0,
        }
    }

    /// True when this entry contains a valid pointer to a record.
    pub fn is_valid(&self) -> bool {
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
pub(super) struct IndexTable {
    front: Option<IndexEntry>,   // Position of the oldest live log record.
    entries: Vec<IndexEntry>,    // Array of entries covering all data region segments.
    segment_size: MemorySize,    // Size of each data region segment in bytes.
    result_max_size: MemorySize, // Maximum size of results to return.
    data_capacity: MemorySize,   // Total capacity of the data region.
}

impl IndexTable {
    /// Creates a table that partitions the data region into fixed-size segments.
    /// If no entries are provided, all segments start out invalid.
    pub fn new(
        front: Option<IndexEntry>, // front might be empty if there are no log records yet.
        data_capacity: MemorySize,
        index_table_pages: u16,
        result_max_size: MemorySize,
        entries: Vec<IndexEntry>,
    ) -> Self {
        let total_size_max = index_table_pages as usize * PAGE_SIZE;
        let entry_size = INDEX_ENTRY_SIZE.get() as usize;
        debug_assert!(entry_size > 0);
        let entries_count = total_size_max / entry_size;
        debug_assert!(entries_count > 0);
        // Use ceiling division to ensure segment_size is at least 1, even if data_capacity < entries_count.
        // This prevents a segment size of 0 which would break indexing.
        let segment_size = (data_capacity.get() as usize).div_ceil(entries_count);
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
            result_max_size,
            data_capacity,
        }
    }

    /// Records the most recent log entry associated with the segment that
    /// contains `position`.
    ///
    /// This operation assumes that log records arrive in strictly increasing
    /// `idx` and non-decreasing `timestamp` order — meaning each update
    /// corresponds to a newer record than any previously stored one.
    /// Because segments keep only the newest record, providing an
    /// out-of-order record would silently overwrite newer data and corrupt
    /// segment ordering.
    ///
    /// IMPORTANT: callers must guarantee monotonic `idx` and `timestamp`
    /// progression.
    pub fn update(&mut self, position: MemoryPosition, record: &LogRecord) {
        if self.front.is_none() {
            // First record being added, initialize front.
            self.front = Some(IndexEntry::new(position, record));
        }
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

    /// Return all raw entries, including invalid ones.
    pub fn raw_entries(&self) -> &Vec<IndexEntry> {
        &self.entries
    }

    /// Return all valid entries at or after `front`, sorted by increasing idx.
    /// Used to narrow down searches without scanning the entire region.
    pub fn valid_sorted_entries(&self) -> Vec<IndexEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid log entries.
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

    /// Returns the maximum allowed result size.
    pub fn result_max_size(&self) -> MemorySize {
        self.result_max_size
    }

    /// Returns an approximate [start, end] range of index entries when no filter is provided.
    ///
    /// Returns only the most recent records (tail), trimming the older ones from the start.
    /// The range size is ≤ `result_max_size + segment_size`.
    pub fn no_filter_approx_range(&self) -> Option<(IndexEntry, IndexEntry)> {
        let entries = self.valid_sorted_entries();
        if entries.is_empty() {
            return None;
        }
        let end_inclusive = entries.last().unwrap();
        let mut start_inclusive = end_inclusive;
        let threshold = self.result_max_size() + self.segment_size;
        for entry in entries.iter().rev() {
            if self.range_size(entry, end_inclusive) > threshold {
                break;
            }
            start_inclusive = entry;
        }
        Some((*start_inclusive, *end_inclusive))
    }

    /// Returns an approximate start of the range when filter is provided.
    ///
    /// The value might be `segment_size` away from the actual start.
    pub fn find_approx_start(&self, filter: FetchCanisterLogsFilter) -> Option<IndexEntry> {
        match filter {
            FetchCanisterLogsFilter::ByIdx(range) => self.find_start_by_key(range.start, |e| e.idx),
            FetchCanisterLogsFilter::ByTimestampNanos(range) => {
                self.find_start_by_key(range.start, |e| e.timestamp)
            }
        }
    }

    /// Returns an approximate start of the range when filter is provided.
    ///
    /// The value might be `segment_size` away from the actual start.
    fn find_start_by_key(&self, key: u64, key_fn: fn(&IndexEntry) -> u64) -> Option<IndexEntry> {
        let entries = self.valid_sorted_entries();
        if entries.is_empty() {
            return None;
        }
        let start = match entries.binary_search_by_key(&key, key_fn) {
            Ok(idx) => entries[idx],      // Exact match.
            Err(0) => entries[0],         // No match, below range, return first.
            Err(idx) => entries[idx - 1], // No match, left fallback.
        };
        Some(start)
    }

    /// Returns the total byte size of the range from the start of `from`
    /// to the end of `to` (both inclusive), correctly handling ring-buffer wraparound.
    fn range_size(&self, from: &IndexEntry, to: &IndexEntry) -> MemorySize {
        let from_pos = from.position;
        let to_pos = self.advance(to.position, MemorySize::new(to.bytes_len as u64));
        if to_pos >= from_pos {
            to_pos - from_pos // no wrap
        } else {
            debug_assert!(self.data_capacity.get() > 0);
            (self.data_capacity + to_pos) - from_pos // wrap
        }
    }

    fn advance(&self, position: MemoryPosition, distance: MemorySize) -> MemoryPosition {
        debug_assert!(self.data_capacity.get() > 0);
        debug_assert!(distance.get() > 0);
        (position + distance) % self.data_capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_management_canister_types_private::FetchCanisterLogsRange;

    const KB: u64 = 1000;
    const MB: u64 = 1000 * KB;

    const TEST_DATA_CAPACITY: MemorySize = MemorySize::new(10 * MB);
    const TEST_NO_WRAP_POSITION: MemoryPosition = MemoryPosition::new(3 * MB);
    const TEST_WRAP_POSITION: MemoryPosition = MemoryPosition::new(9 * MB);
    const TEST_RESULT_MAX_SIZE: MemorySize = MemorySize::new(2 * MB);
    const TEST_INDEX_TABLE_PAGES: u16 = 1;
    // Index table of 1 page holds 4096 / 28 bytes per entry = 146 entries max
    // Average segment size: 10 MB / 146 = ~70 KB
    // Individual test record size: 10 KB
    const RECORD_HEADER_SIZE: u64 = 8 + 8 + 4; // idx + timestamp + len
    const TEST_RECORD_CONTENT_SIZE: MemorySize = MemorySize::new(10 * KB - RECORD_HEADER_SIZE);
    // Safety margin to keep “small” and “big” cases clearly separated from the 2 MB limit
    const MARGIN: MemorySize = MemorySize::new(4 * 70 * KB);

    // Small log – comfortably below the max result limit
    const TEST_LOG_SIZE_SMALL: MemorySize = MemorySize::new(1_500 * KB); // 1.5 MB or 150 records
    const _: () = assert!(TEST_LOG_SIZE_SMALL.get() < TEST_RESULT_MAX_SIZE.get() - MARGIN.get());
    const TEST_SMALL_LOG_RECORDS_COUNT: u64 = 150;

    // Big log – comfortably above the max result limit
    const TEST_LOG_SIZE_BIG: MemorySize = MemorySize::new(2_500 * KB); // 2.5 MB or 250 records
    const _: () = assert!(TEST_LOG_SIZE_BIG.get() > TEST_RESULT_MAX_SIZE.get() + MARGIN.get());
    const TEST_BIG_LOG_RECORDS_COUNT: u64 = 250;

    fn make_log_record(idx: u64, ts: u64, record_content_size: u64) -> LogRecord {
        LogRecord {
            idx,
            timestamp: ts,
            len: record_content_size as u32,
            content: vec![], // Not needed for tests.
        }
    }

    fn advance(
        position: MemoryPosition,
        distance: u64,
        data_capacity: MemorySize,
    ) -> MemoryPosition {
        debug_assert!(data_capacity.get() > 0);
        debug_assert!(distance > 0);
        (position + MemorySize::new(distance)) % data_capacity
    }

    fn make_table_with_config(
        data_capacity: MemorySize,
        index_table_pages: u16,
        result_max_size: MemorySize,
        record_content_size: MemorySize,
        log_size: MemorySize,
        start_pos: MemoryPosition,
        start_idx: u64,
    ) -> IndexTable {
        let mut table = IndexTable::new(
            None,
            data_capacity,
            index_table_pages,
            result_max_size,
            vec![],
        );
        let mut pos = start_pos;
        let mut idx = start_idx;
        let mut total_size = 0;
        loop {
            let rec = make_log_record(idx, idx * 1_000_000, record_content_size.get());
            let bytes_len = rec.bytes_len() as u64;
            if total_size + bytes_len > log_size.get() {
                break;
            }
            table.update(pos, &rec);
            total_size += bytes_len;
            pos = advance(pos, bytes_len, data_capacity);
            idx += 1;
        }
        table
    }

    fn filter_by_idx(start: u64, end: u64) -> FetchCanisterLogsFilter {
        FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange { start, end })
    }

    fn filter_by_timestamp(start: u64, end: u64) -> FetchCanisterLogsFilter {
        FetchCanisterLogsFilter::ByTimestampNanos(FetchCanisterLogsRange { start, end })
    }

    fn records_count(start: &IndexEntry, end: &IndexEntry) -> u64 {
        end.idx - start.idx + 1
    }

    #[test]
    fn empty_table_returns_none() {
        let table = IndexTable::new(
            None,
            TEST_DATA_CAPACITY,
            TEST_INDEX_TABLE_PAGES,
            TEST_RESULT_MAX_SIZE,
            vec![],
        );
        assert!(table.no_filter_approx_range().is_none());
        assert!(
            table
                .find_approx_start(filter_by_idx(0, u64::MAX))
                .is_none()
        );
        assert!(
            table
                .find_approx_start(filter_by_timestamp(0, u64::MAX))
                .is_none()
        );
    }

    #[test]
    fn single_record_returns_same_start_and_end() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let start_idx = 0;
            let fake_record = make_log_record(1, 1, TEST_RECORD_CONTENT_SIZE.get());
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                MemorySize::new(fake_record.bytes_len() as u64), // log size of a single record.
                start_position,
                start_idx,
            );

            let (start, end) = table.no_filter_approx_range().expect("range present");
            // Assert start and end point to the same single record at start_idx.
            assert_eq!(start.idx, start_idx);
            assert_eq!(start, end);
            assert_eq!(records_count(&start, &end), 1);

            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
                    start: 0,
                    end: u64::MAX,
                }))
                .expect("start present");
            assert_eq!(start.idx, start_idx);

            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByTimestampNanos(
                    FetchCanisterLogsRange {
                        start: 0,
                        end: u64::MAX,
                    },
                ))
                .expect("start present");
            assert_eq!(start.idx, start_idx);
        }
    }

    #[test]
    fn small_log_no_filter_returns_all() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let start_idx = 0;
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                TEST_LOG_SIZE_SMALL,
                start_position,
                start_idx,
            );
            let (start, end) = table.no_filter_approx_range().expect("range present");
            assert_eq!(start.idx, start_idx); // Beginning is not trimmed.
            assert_eq!(records_count(&start, &end), TEST_SMALL_LOG_RECORDS_COUNT);

            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
                    start: 0,
                    end: u64::MAX,
                }))
                .expect("start present");
            assert_eq!(start.idx, start_idx); // Beginning is not trimmed.

            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByTimestampNanos(
                    FetchCanisterLogsRange {
                        start: 0,
                        end: u64::MAX,
                    },
                ))
                .expect("start present");
            assert_eq!(start.idx, start_idx); // Beginning is not trimmed.
        }
    }

    #[test]
    fn small_log_filter_by_idx() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                TEST_LOG_SIZE_SMALL,
                start_position,
                0,
            );
            let (no_filter_start, no_filter_end) =
                table.no_filter_approx_range().expect("range present");
            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
                    start: 10,
                    end: 20,
                }))
                .expect("start present");
            // Assert filtered range is within no-filter range.
            assert!(no_filter_start.idx <= start.idx);
            assert!(start.idx <= no_filter_end.idx);
        }
    }

    #[test]
    fn small_log_filter_by_timestamp() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                TEST_LOG_SIZE_SMALL,
                start_position,
                0,
            );
            let (no_filter_start, no_filter_end) =
                table.no_filter_approx_range().expect("range present");
            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByTimestampNanos(
                    FetchCanisterLogsRange {
                        start: 10_000_000,
                        end: 20_000_000,
                    },
                ))
                .expect("start present");
            // Assert filtered range is within no-filter range.
            assert!(no_filter_start.idx <= start.idx);
            assert!(start.idx <= no_filter_end.idx);
        }
    }

    #[test]
    fn big_log_no_filter_returns_tail() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let start_idx = 0;
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                TEST_LOG_SIZE_BIG,
                start_position,
                start_idx,
            );
            let (start, end) = table.no_filter_approx_range().expect("range present");
            assert_ne!(start.idx, start_idx); // Beginning is trimmed.
            assert!(start.idx < end.idx);
            // Assert distance is above max result size but within one segment size.
            let distance = table.range_size(&start, &end);
            assert!(distance >= table.result_max_size());
            assert!(distance <= table.result_max_size() + table.segment_size);
            assert!(records_count(&start, &end) < TEST_BIG_LOG_RECORDS_COUNT);
        }
    }

    #[test]
    fn big_log_filter_by_idx() {
        for start_position in [TEST_NO_WRAP_POSITION, TEST_WRAP_POSITION] {
            let start_idx = 0;
            let filter_start_idx = 10;
            let table = make_table_with_config(
                TEST_DATA_CAPACITY,
                TEST_INDEX_TABLE_PAGES,
                TEST_RESULT_MAX_SIZE,
                TEST_RECORD_CONTENT_SIZE,
                TEST_LOG_SIZE_BIG,
                start_position,
                start_idx,
            );

            // Short range query within max result size.
            // 180 records * 10 KB < 2 MB limit
            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
                    start: filter_start_idx,
                    end: filter_start_idx + 180,
                }))
                .expect("start present");
            assert!(start.idx <= filter_start_idx); // Beginning is not trimmed.

            // Long range query exceeding max result size.
            // 220 records * 10 KB > 2 MB limit
            let start = table
                .find_approx_start(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
                    start: filter_start_idx,
                    end: filter_start_idx + 220,
                }))
                .expect("start present");
            assert!(start.idx <= filter_start_idx); // Beginning is not trimmed.
        }
    }
}
