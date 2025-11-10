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

    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        let header = self.io.read_header();
        if header.is_empty() {
            return Vec::new();
        }

        let (start, end) = self.io.read_lookup_table().get_range(&filter);
        let mut result = Vec::new();
        let mut position = start;
        let filter_ref = filter.as_ref();

        while position <= end {
            let abs_position = header.data_offset + position;
            let record = match self.io.read_record(abs_position) {
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

    /// Removes the first log record and returns it, or None if the ring buffer is empty.
    pub fn pop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.io.read_header();
        if h.is_empty() {
            return None;
        }
        let record = self.io.read_record(h.data_offset + h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = (h.data_head + removed_size) % h.data_capacity;
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.write_header(&h);
        Some(record)
    }

    /// Appends a new log record to the back of the ring buffer.
    pub fn push_back(&mut self, record: &LogRecord) {
        let bytes: Vec<u8> = record.into();
        let added_size = MemorySize::new(bytes.len() as u64);
        self.make_free_space_within_limit(added_size);
        // writing new entry into the buffer has 2 cases:
        // 1) there is enough space at the end of the buffer
        // 2) we need to wrap around
        let mut h = self.io.read_header();
        let tail = h.data_offset + h.data_tail;
        let remaining_size = h.data_capacity - h.data_tail;
        if added_size <= remaining_size {
            // case 1: no wrap
            self.io.write_bytes(tail, &bytes);
        } else {
            // case 2: wrap
            let (first, second) = bytes.split_at(remaining_size.as_usize());
            self.io.write_bytes(tail, first);
            self.io.write_bytes(h.data_offset, second);
        }
        let last_record_position = h.data_tail;
        h.data_tail = (h.data_tail + added_size) % h.data_capacity;
        h.data_size = h.data_size.saturating_add(added_size);
        h.next_idx = record.idx + 1;
        self.io.write_header(&h);

        // Update the lookup table after writing the record and updating the header.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::system_state::log_memory_store::memory::MemorySize;
    use crate::page_map::PageMap;

    #[test]
    fn test_ring_buffer_initialization() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(2 * 1024 * 1024); // 2 MB
        let ring_buffer = RingBuffer::new(page_map, data_capacity);
        assert_eq!(ring_buffer.capacity(), data_capacity.get() as usize);
        assert_eq!(ring_buffer.used_space(), 0);
        assert_eq!(ring_buffer.next_id(), 0);
    }

    fn log_record(idx: u64, ts_nanos: u64, message: &str) -> LogRecord {
        LogRecord {
            idx,
            ts_nanos,
            len: message.len() as u32,
            content: message.as_bytes().to_vec(),
        }
    }

    #[test]
    fn push_and_pop_order_preserved() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(4096);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let a = log_record(0, 100, "a");
        let b = log_record(1, 200, "bb");

        rb.push_back(&a);
        rb.push_back(&b);

        assert_eq!(rb.used_space(), a.bytes_len() + b.bytes_len());
        assert_eq!(rb.pop_front().unwrap(), a);
        assert_eq!(rb.pop_front().unwrap(), b);
        assert!(rb.pop_front().is_none());
    }

    #[test]
    fn wraps_around_correctly() {
        let page_map = PageMap::new_for_testing();
        // tiny capacity to force wrap quickly
        let data_capacity = MemorySize::new(128);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        // push until wrap occurs
        for i in 0..10u64 {
            let r = log_record(i, i * 10 + 1, "x");
            rb.push_back(&r);
            // Keep popping occasionally to exercise head movement
            if i % 3 == 0 {
                let _ = rb.pop_front();
            }
        }

        // drain remaining and ensure order is monotonic by idx
        let mut last_idx = None;
        while let Some(rec) = rb.pop_front() {
            if let Some(prev) = last_idx {
                assert!(rec.idx > prev);
            }
            last_idx = Some(rec.idx);
        }
    }

    #[test]
    fn evicts_old_records_when_full() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(256);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        // append many records until buffer forces eviction
        for i in 0..20u64 {
            let r = log_record(i, i, "payload");
            rb.push_back(&r);
        }

        // used_space must be <= capacity and next idx advanced
        assert!(rb.used_space() <= data_capacity.get() as usize);
        assert!(rb.next_id() > 0);
        // popping all remaining records should produce increasing idxs
        let mut last = None;
        while let Some(rec) = rb.pop_front() {
            if let Some(prev) = last {
                assert!(rec.idx > prev);
            }
            last = Some(rec.idx);
        }
    }

    #[test]
    fn lookup_table_and_records_filtering() {
        let page_map = PageMap::new_for_testing();
        let data_capacity = MemorySize::new(4096);
        let mut rb = RingBuffer::new(page_map, data_capacity);

        let r0 = log_record(0, 1000, "alpha");
        let r1 = log_record(1, 2000, "beta");
        let r2 = log_record(2, 3000, "gamma");

        rb.push_back(&r0);
        rb.push_back(&r1);
        rb.push_back(&r2);

        // No filter
        let res = rb.records(None);
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].idx, 0);
        assert_eq!(res[1].idx, 1);
        assert_eq!(res[2].idx, 2);

        // Filter by idx range [1, 2)
        let res = rb.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 1, end: 2 },
        )));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].idx, 1);

        // Filter by timestamp range [1500, 3500)
        let res = rb.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: 1500,
                end: 3500,
            },
        )));
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].idx, 1);
        assert_eq!(res[1].idx, 2);
    }
}

/*
bazel test //rs/replicated_state/... \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=test_ring_buffer_push_pop
*/
