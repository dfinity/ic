use crate::canister_state::system_state::log_memory_store::{
    header::Header,
    log_record::LogRecord,
    memory::{MemoryAddress, MemorySize},
    struct_io::StructIO,
};
use crate::page_map::{PAGE_SIZE, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, DataSize, FetchCanisterLogsFilter};

// PageMap file layout.
// Header layout constants.
pub const HEADER_OFFSET: MemoryAddress = MemoryAddress::new(0);
pub const HEADER_SIZE: MemorySize = MemorySize::new(PAGE_SIZE as u64);
pub const MAGIC: &[u8; 3] = b"CLB"; // Canister Log Buffer
// Index table layout constants.
pub const INDEX_TABLE_OFFSET: MemoryAddress = HEADER_OFFSET.add_size(HEADER_SIZE);
pub const INDEX_TABLE_PAGES: usize = 1;
pub const INDEX_TABLE_SIZE: MemorySize = MemorySize::new((INDEX_TABLE_PAGES * PAGE_SIZE) as u64);
pub const INDEX_ENTRY_SIZE: MemorySize = MemorySize::new(28);
pub const INDEX_ENTRY_COUNT_MAX: u64 = INDEX_TABLE_SIZE.get() / INDEX_ENTRY_SIZE.get();
// Data region layout constants.
pub const DATA_REGION_OFFSET: MemoryAddress = INDEX_TABLE_OFFSET.add_size(INDEX_TABLE_SIZE);

// Ring buffer constraints.

/// Maximum total size of log records returned in a single message.
pub const RESULT_MAX_SIZE: MemorySize = MemorySize::new(2_000_000);
const _: () = assert!(RESULT_MAX_SIZE.get() <= 2_000_000, "Exceeds 2 MB");

// With index table of 1 page (4 KiB) and 28 bytes per entry -> 146 entries max.
// With 2 MB result max size limit we want each index entry segment to be under
// say 20% of that (400 KB). So 146 segments turns into ~55 MB total data capacity.
// Small segments help to reduce work on refining log records filtering
// when fetching logs.
pub const DATA_CAPACITY_MAX: MemorySize = MemorySize::new(55_000_000); // 55 MB
const DATA_SEGMENT_SIZE_MAX: u64 = DATA_CAPACITY_MAX.get() / INDEX_ENTRY_COUNT_MAX;
// Ensure data segment size is significantly smaller than max result size, say 20%.
const _: () = assert!(5 * DATA_SEGMENT_SIZE_MAX <= RESULT_MAX_SIZE.get());

pub const DATA_CAPACITY_MIN: usize = PAGE_SIZE;
const _: () = assert!(PAGE_SIZE <= DATA_CAPACITY_MIN); // data capacity must be at least one page.

pub(crate) struct RingBuffer {
    io: StructIO,
}

impl RingBuffer {
    /// Creates a new ring buffer with the given data capacity.
    pub fn new(page_map: PageMap, data_capacity: MemorySize) -> Self {
        assert!(
            data_capacity <= DATA_CAPACITY_MAX,
            "data capacity exceeds maximum"
        );
        let mut io = StructIO::new(page_map);
        io.save_header(&Header::new(data_capacity));

        Self { io }
    }

    /// Returns an existing ring buffer if present, or initializes a new one.
    pub fn load_or_new(page_map: PageMap, data_capacity: MemorySize) -> Self {
        let io = StructIO::new(page_map);
        if io.load_header().magic != *MAGIC {
            // Not initialized yet — set up a new header.
            return Self::new(io.to_page_map(), data_capacity);
        }

        Self { io }
    }

    pub fn to_page_map(&self) -> PageMap {
        self.io.to_page_map()
    }

    /// Returns the total allocated bytes for the ring buffer
    /// including header, index table and data region.
    pub fn total_allocated_bytes(&self) -> usize {
        let header = self.io.load_header();
        HEADER_SIZE.get() as usize
            + header.index_table_pages as usize * PAGE_SIZE
            + header.data_capacity.get() as usize
    }

    /// Returns the data capacity of the ring buffer.
    pub fn byte_capacity(&self) -> usize {
        self.io.load_header().data_capacity.get() as usize
    }

    /// Returns the data size of the ring buffer.
    pub fn bytes_used(&self) -> usize {
        self.io.load_header().data_size.get() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.bytes_used() == 0
    }

    pub fn next_id(&self) -> u64 {
        self.io.load_header().next_idx
    }

    #[cfg(test)]
    fn append(&mut self, record: &CanisterLogRecord) {
        self.append_log(vec![record.clone()]);
    }

    pub fn append_log(&mut self, records: Vec<CanisterLogRecord>) {
        let mut index_table = self.io.load_index_table();
        for r in records {
            let record = LogRecord::from(r);

            // Check that records are added in order, otherwise it breaks the index.
            let h = self.io.load_header();
            if record.idx < h.next_idx {
                debug_assert!(false, "Log record idx must be >= than next idx");
                continue;
            }
            if record.timestamp < h.max_timestamp {
                debug_assert!(false, "Log record timestamp must be >= than max timestamp");
                continue;
            }

            let added_size = MemorySize::new(record.bytes_len() as u64);
            let capacity = MemorySize::new(self.byte_capacity() as u64);
            if added_size > capacity {
                debug_assert!(false, "Log record size exceeds ring buffer capacity");
                return;
            }
            self.make_free_space(added_size);

            // Save the record at the tail position.
            let mut h = self.io.load_header();
            self.io.save_record(h.data_tail, &record);

            // Update header with new tail position, size and next idx.
            let position = h.data_tail;
            h.data_tail = h.advance_position(position, added_size);
            h.data_size = h.data_size.saturating_add(added_size);
            h.next_idx = record.idx + 1;
            h.max_timestamp = record.timestamp;
            self.io.save_header(&h);

            // Update the index table with the latest record position.
            index_table.update(position, &record);
        }
        // It's fine to save the index table only once after saving all the records.
        self.io.save_index_table(&index_table);
    }

    fn make_free_space(&mut self, added_size: MemorySize) {
        let capacity = MemorySize::new(self.byte_capacity() as u64);
        while MemorySize::new(self.bytes_used() as u64) + added_size > capacity {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }
    }

    fn pop_front(&mut self) -> Option<CanisterLogRecord> {
        let mut h = self.io.load_header();
        let record = self.io.load_record(h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = h.advance_position(h.data_head, removed_size);
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.save_header(&h);
        // No need to update the index here since front entry is never
        // stored in the PageMap but rather computed on table load.
        Some(CanisterLogRecord {
            idx: record.idx,
            timestamp_nanos: record.timestamp,
            content: record.content,
        })
    }

    /// Returns records according to an optional filter.
    ///
    /// - No filter: return the most recent records (tail), trimming older ones
    ///   from the start so total data size ≤ result_max_size.
    /// - With filter: return the most oldest records (head), trimming newer ones
    ///   from the end so total data size ≤ result_max_size.
    pub fn records(&self, maybe_filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        let header = self.io.load_header();
        let index = self.io.load_index_table();
        let size_limit = index.result_max_size().get() as usize;

        match maybe_filter {
            None => {
                // Determine approximate start/end of the tail range.
                let (start_entry, end_entry) = match index.no_filter_approx_range() {
                    None => return Vec::new(),
                    Some(range) => range,
                };

                // Load the contiguous records in [start, end].
                let mut records: Vec<CanisterLogRecord> = Vec::new();
                let mut pos = start_entry.position;
                while let Some(record) = self.io.load_record(pos) {
                    if record.idx > end_entry.idx {
                        break;
                    }
                    pos = header.advance_position(pos, MemorySize::new(record.bytes_len() as u64));
                    records.push(CanisterLogRecord::from(record));
                }

                // Trim older records from the front so total data size ≤ limit.
                let mut total_size = 0;
                let mut start = records.len();
                for rec in records.iter().rev() {
                    total_size += rec.data_size();
                    if total_size > size_limit {
                        break;
                    }
                    start -= 1;
                }
                records[start..].to_vec()
            }

            Some(filter) if !filter.is_valid() => Vec::new(),

            Some(filter) => {
                // Find an approximate start where matching records may begin.
                let approx_start = match index.find_approx_start(filter) {
                    None => return Vec::new(),
                    Some(e) => e,
                };

                // Scan forward from approx start — collect matching records until limit
                // or until a non-matching record is seen after we started collecting.
                let mut records: Vec<CanisterLogRecord> = Vec::new();
                let mut total_size = 0;
                let mut pos = approx_start.position;
                while let Some(record) = self.io.load_record(pos) {
                    let bytes = record.bytes_len();
                    if record.matches(&filter) {
                        let canister_log_record = CanisterLogRecord::from(record);
                        total_size += canister_log_record.data_size();
                        if total_size > size_limit {
                            break;
                        }
                        records.push(canister_log_record);
                    } else if !records.is_empty() {
                        // Stop after the first non-matching record once we have matches.
                        break;
                    }
                    pos = header.advance_position(pos, MemorySize::new(bytes as u64));
                }
                records
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::system_state::log_memory_store::memory::MemorySize;
    use crate::page_map::PageMap;
    use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsRange};

    const TEST_DATA_CAPACITY: MemorySize = MemorySize::new(2_000_000); // 2 MB

    fn log_record(idx: u64, timestamp: u64, message: &str) -> CanisterLogRecord {
        CanisterLogRecord {
            idx,
            timestamp_nanos: timestamp,
            content: message.as_bytes().to_vec(),
        }
    }

    /// Calculates the byte size inside the log memory store.
    fn bytes_len(r: &CanisterLogRecord) -> usize {
        LogRecord::from(r.clone()).bytes_len()
    }

    #[test]
    fn test_initialization() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = TEST_DATA_CAPACITY;

        let rb = RingBuffer::new(page_map, data_capacity);

        assert_eq!(rb.byte_capacity(), data_capacity.get() as usize);
        assert_eq!(rb.bytes_used(), 0);
        assert_eq!(rb.next_id(), 0);
    }

    #[test]
    fn test_push_and_pop_order_preserved() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = TEST_DATA_CAPACITY;
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let r0 = log_record(0, 100, "a");
        let r1 = log_record(1, 200, "bb");
        rb.append(&r0);
        rb.append(&r1);

        assert_eq!(rb.bytes_used(), bytes_len(&r0) + bytes_len(&r1));
        assert_eq!(rb.pop_front().unwrap(), r0);
        assert_eq!(rb.pop_front().unwrap(), r1);
        assert!(rb.pop_front().is_none());
    }

    #[test]
    fn test_exact_fit_no_eviction() {
        let record_size: usize = 25;
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(3 * record_size as u64);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let r0 = log_record(0, 100, "12345");
        assert_eq!(bytes_len(&r0), record_size);
        let r1 = log_record(1, 200, "12345");
        let r2 = log_record(2, 300, "12345");
        let r3 = log_record(3, 400, "12345");

        // Add and remove one record to test wrap-around.
        rb.append(&r0);
        rb.pop_front().unwrap();

        // Now add three records that exactly fit the capacity.
        rb.append(&r1);
        rb.append(&r2);
        rb.append(&r3);

        assert_eq!(rb.pop_front().unwrap(), r1);
        assert_eq!(rb.pop_front().unwrap(), r2);
        assert_eq!(rb.pop_front().unwrap(), r3);
    }

    #[test]
    fn test_eviction_when_adding_exceeds_capacity() {
        let record_size: usize = 25;
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(3 * record_size as u64);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let r0 = log_record(0, 100, "12345");
        assert_eq!(bytes_len(&r0), record_size);
        let r1 = log_record(1, 200, "12345");
        let r2 = log_record(2, 300, "12345");
        let r3 = log_record(3, 400, "123456"); // 26 bytes to force eviction.

        // Add and remove one record to test wrap-around.
        rb.append(&r0);
        rb.pop_front().unwrap();

        // Now add three records, the last one should evict the first.
        rb.append(&r1);
        rb.append(&r2);
        rb.append(&r3);

        assert_eq!(rb.pop_front().unwrap(), r2);
        assert_eq!(rb.pop_front().unwrap(), r3);
        assert!(rb.pop_front().is_none());
    }

    #[test]
    fn test_wraps_without_eviction() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(137);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        // Push many records to cause wrap-around without eviction.
        let mut pushed: Vec<CanisterLogRecord> = vec![];
        let mut popped: Vec<CanisterLogRecord> = vec![];
        for i in 0..1_000 {
            let record = log_record(i, i * 100, "12345");
            // Free space until the new record fits, popped records are collected.
            while rb.bytes_used() + bytes_len(&record) > rb.byte_capacity() {
                popped.push(rb.pop_front().expect("expected record to pop"));
            }
            rb.append(&record);
            pushed.push(record);
        }
        while let Some(r) = rb.pop_front() {
            popped.push(r);
        }

        // Every pushed record was eventually popped in the same order.
        assert_eq!(pushed.len(), popped.len(),);
        assert_eq!(pushed, popped, "Sequence mismatch — push/pop order differs");
    }

    #[test]
    fn test_lookup_table_and_records_filtering() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = TEST_DATA_CAPACITY;
        let mut rb = RingBuffer::new(page_map, data_capacity);
        let r0 = log_record(0, 1000, "alpha");
        let r1 = log_record(1, 2000, "beta");
        let r2 = log_record(2, 3000, "gamma");
        rb.append(&r0);
        rb.append(&r1);
        rb.append(&r2);

        // No filter.
        let res = rb.records(None);
        assert_eq!(
            res,
            vec![
                log_record(0, 1000, "alpha"),
                log_record(1, 2000, "beta"),
                log_record(2, 3000, "gamma")
            ]
        );

        // Filter by idx range [1, 2).
        let res = rb.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 1, end: 2 },
        )));
        assert_eq!(res, vec![log_record(1, 2000, "beta"),]);

        // Filter by timestamp range [1500, 3500).
        let res = rb.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: 1500,
                end: 3500,
            },
        )));
        assert_eq!(
            res,
            vec![log_record(1, 2000, "beta"), log_record(2, 3000, "gamma")]
        );
    }
}
