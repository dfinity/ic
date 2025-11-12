use crate::canister_state::system_state::log_memory_store::{
    header::HeaderV1,
    log_record::LogRecord,
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    struct_io::StructIO,
};
use crate::page_map::{PAGE_SIZE, PageIndex, PageMap};
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsFilter, FetchCanisterLogsRange,
};
use ic_sys::PageBytes;

const MAGIC: &[u8; 3] = b"LMS";
pub(crate) const HEADER_OFFSET: MemoryAddress = MemoryAddress::new(0);
pub(crate) const V1_HEADER_SIZE: MemorySize = MemorySize::new(PAGE_SIZE as u64);
pub(crate) const V1_LOOKUP_TABLE_OFFSET: MemoryAddress = HEADER_OFFSET.add_size(V1_HEADER_SIZE);

const LOOKUP_TABLE_PAGES: u16 = 1; // For buffer up to 2 MiB data capacity 1 page is enough.

struct RingBuffer {
    io: StructIO,
}

impl RingBuffer {
    pub fn new(page_map: PageMap, data_capacity: MemorySize) -> Self {
        let mut io = StructIO::new(page_map);
        let data_offset = V1_LOOKUP_TABLE_OFFSET.add_size(MemorySize::new(
            (LOOKUP_TABLE_PAGES as u64) * (PAGE_SIZE as u64),
        ));
        let header = HeaderV1 {
            magic: *MAGIC,
            version: 1,
            lookup_table_pages: LOOKUP_TABLE_PAGES,
            lookup_entries_count: 0,
            data_offset,
            data_capacity,
            data_size: MemorySize::new(0),
            data_head: MemoryPosition::new(0),
            data_tail: MemoryPosition::new(0),
            next_idx: 0,
        };
        io.write_header(&header);

        Self { io }
    }

    pub fn init(page_map: PageMap, data_capacity: MemorySize) -> Self {
        let io = StructIO::new(page_map);
        if io.read_header().magic != *MAGIC {
            // Not initialized yet, create a new instance.
            return Self::new(io.into_page_map(), data_capacity);
        }
        Self { io }
    }

    pub fn dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        self.io.dirty_pages()
    }

    pub fn into_page_map(self) -> PageMap {
        self.io.into_page_map()
    }

    pub fn capacity(&self) -> usize {
        self.io.read_header().data_capacity.get() as usize
    }

    pub fn used_space(&self) -> usize {
        self.io.read_header().data_size.get() as usize
    }

    pub fn next_id(&self) -> u64 {
        self.io.read_header().next_idx
    }

    /// Remove and return the first log record from the ring buffer, `None` if empty.
    pub fn pop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.io.read_header();
        let record = self.io.read_record(h.data_head)?;

        // Update header to drop the record.
        // Lookup table unaffected, since it tracks only latest per bucket.
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = h.advance_position(h.data_head, removed_size);
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.write_header(&h);

        Some(record)
    }

    /// Appends a new log record to the back of the ring buffer.
    pub fn push_back(&mut self, record: &LogRecord) {
        // Ensure there is enough free space for the new record.
        let added_size = MemorySize::new(record.bytes_len() as u64);
        self.make_free_space_within_limit(added_size);

        // Write the record at the tail position.
        let mut h = self.io.read_header();
        self.io.write_record(record, h.data_tail);

        // Update header with new tail position, size and next idx.
        let last_record_position = h.data_tail;
        h.data_tail = h.advance_position(h.data_tail, added_size);
        h.data_size = h.data_size.saturating_add(added_size);
        h.next_idx = record.idx + 1;
        self.io.write_header(&h);

        // Update lookup table after writing the record and updating the header.
        self.update_lookup_table_last(record, last_record_position);
    }

    /// Ensures there is enough free space for bytes_len by removing old records.
    fn make_free_space_within_limit(&mut self, bytes_len: MemorySize) {
        while self.used_space() + bytes_len.as_usize() > self.capacity() {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }
    }

    fn update_lookup_table_last(&mut self, record: &LogRecord, position: MemoryPosition) {
        let mut lookup_table = self.io.read_lookup_table();
        lookup_table.update_last(record, position);
        self.io.write_lookup_table(&lookup_table);
    }

    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        let header = self.io.read_header();
        if header.is_empty() {
            return Vec::new();
        }

        let range = self.io.read_lookup_table().get_range(&filter);
        if range.is_none() {
            return Vec::new();
        }
        let (start, end) = range.unwrap();
        let mut result = Vec::new();
        let mut position = start;
        let filter_ref = filter.as_ref();

        while position <= end {
            let record = match self.io.read_record(position) {
                Some(r) => r,
                None => break, // Stop when no more records can be read.
            };
            if filter_ref.is_none_or(|f| record.matches(f)) {
                result.push(record.to_canister_log_record());
            }
            let record_size = MemorySize::new(record.bytes_len() as u64);
            if record_size.get() == 0 {
                break; // Prevent infinite loop on corrupted record.
            }
            position = (position + record_size) % header.data_capacity;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::system_state::log_memory_store::memory::MemorySize;
    use crate::page_map::PageMap;

    const TEST_DATA_CAPACITY: MemorySize = MemorySize::new(2_000_000); // 2 MB

    fn log_record(idx: u64, ts_nanos: u64, message: &str) -> LogRecord {
        LogRecord {
            idx,
            ts_nanos,
            len: message.len() as u32,
            content: message.as_bytes().to_vec(),
        }
    }

    fn canister_log_record(idx: u64, ts_nanos: u64, message: &str) -> CanisterLogRecord {
        CanisterLogRecord {
            idx,
            timestamp_nanos: ts_nanos,
            content: message.as_bytes().to_vec(),
        }
    }

    #[test]
    fn test_initialization() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = TEST_DATA_CAPACITY;

        let ring_buffer = RingBuffer::new(page_map, data_capacity);

        assert_eq!(ring_buffer.capacity(), data_capacity.get() as usize);
        assert_eq!(ring_buffer.used_space(), 0);
        assert_eq!(ring_buffer.next_id(), 0);
    }

    #[test]
    fn test_push_and_pop_order_preserved() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = TEST_DATA_CAPACITY;
        let mut ring_buffer = RingBuffer::new(page_map, data_capacity);

        let a = log_record(0, 100, "a");
        let b = log_record(1, 200, "bb");
        ring_buffer.push_back(&a);
        ring_buffer.push_back(&b);

        assert_eq!(ring_buffer.used_space(), a.bytes_len() + b.bytes_len());
        assert_eq!(ring_buffer.pop_front().unwrap(), a);
        assert_eq!(ring_buffer.pop_front().unwrap(), b);
        assert!(ring_buffer.pop_front().is_none());
    }

    #[test]
    fn test_exact_fit_no_eviction() {
        let record_size: usize = 25;
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(3 * record_size as u64);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let r0 = log_record(0, 100, "12345");
        assert_eq!(r0.bytes_len(), record_size);
        let r1 = log_record(1, 200, "12345");
        let r2 = log_record(2, 300, "12345");
        let r3 = log_record(3, 400, "12345");

        // Add and remove one record to test wrap-around.
        rb.push_back(&r0);
        rb.pop_front().unwrap();

        // Now add three records that exactly fit the capacity.
        rb.push_back(&r1);
        rb.push_back(&r2);
        rb.push_back(&r3);

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
        assert_eq!(r0.bytes_len(), record_size);
        let r1 = log_record(1, 200, "12345");
        let r2 = log_record(2, 300, "12345");
        let r3 = log_record(3, 400, "123456"); // 26 bytes to force eviction.

        // Add and remove one record to test wrap-around.
        rb.push_back(&r0);
        rb.pop_front().unwrap();

        // Now add three records, the last one should evict the first.
        rb.push_back(&r1);
        rb.push_back(&r2);
        rb.push_back(&r3);

        assert_eq!(rb.pop_front().unwrap(), r2);
        assert_eq!(rb.pop_front().unwrap(), r3);
        assert!(rb.pop_front().is_none());
    }

    #[test]
    fn test_wraps_without_eviction() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(137);
        let mut ring_buffer = RingBuffer::new(page_map, data_capacity);

        // Push many records to cause wrap-around without eviction.
        let mut pushed: Vec<LogRecord> = vec![];
        let mut popped: Vec<LogRecord> = vec![];
        for i in 0..1_000 {
            let record = log_record(i, i * 100, "12345");
            // Free space until the new record fits, popped records are collected.
            while ring_buffer.used_space() + record.bytes_len() > ring_buffer.capacity() {
                popped.push(ring_buffer.pop_front().expect("expected record to pop"));
            }
            ring_buffer.push_back(&record);
            pushed.push(record);
        }
        while let Some(r) = ring_buffer.pop_front() {
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
        let mut ring_buffer = RingBuffer::new(page_map, data_capacity);
        let r0 = log_record(0, 1000, "alpha");
        let r1 = log_record(1, 2000, "beta");
        let r2 = log_record(2, 3000, "gamma");
        ring_buffer.push_back(&r0);
        ring_buffer.push_back(&r1);
        ring_buffer.push_back(&r2);

        // No filter.
        let res = ring_buffer.records(None);
        assert_eq!(
            res,
            vec![
                canister_log_record(0, 1000, "alpha"),
                canister_log_record(1, 2000, "beta"),
                canister_log_record(2, 3000, "gamma")
            ]
        );

        // Filter by idx range [1, 2).
        let res = ring_buffer.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 1, end: 2 },
        )));
        assert_eq!(res, vec![canister_log_record(1, 2000, "beta"),]);

        // Filter by timestamp range [1500, 3500).
        let res = ring_buffer.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: 1500,
                end: 3500,
            },
        )));
        assert_eq!(
            res,
            vec![
                canister_log_record(1, 2000, "beta"),
                canister_log_record(2, 3000, "gamma")
            ]
        );
    }
}

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=log_memory_store
*/
