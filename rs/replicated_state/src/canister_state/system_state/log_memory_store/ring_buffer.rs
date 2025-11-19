#![allow(dead_code)] // TODO: don't forget to cleanup.

use crate::canister_state::system_state::log_memory_store::{
    header::Header,
    log_record::LogRecord,
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    struct_io::StructIO,
};
use crate::page_map::{PAGE_SIZE, PageIndex, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_sys::PageBytes;

// PageMap file layout.
// Header layout constants.
pub const HEADER_OFFSET: MemoryAddress = MemoryAddress::new(0);
pub const HEADER_RESERVED_SIZE: MemorySize = MemorySize::new(PAGE_SIZE as u64);
pub const HEADER_SIZE: MemorySize = MemorySize::new(56);
pub const MAGIC: &[u8; 3] = b"LMS";
// Index table layout constants.
pub const INDEX_TABLE_OFFSET: MemoryAddress = HEADER_OFFSET.add_size(HEADER_RESERVED_SIZE);
pub const INDEX_TABLE_PAGES: usize = 1;
pub const INDEX_TABLE_SIZE: MemorySize = MemorySize::new((INDEX_TABLE_PAGES * PAGE_SIZE) as u64);
pub const INDEX_ENTRY_SIZE: MemorySize = MemorySize::new(28);
// Data region layout constants.
pub const DATA_REGION_OFFSET: MemoryAddress = INDEX_TABLE_OFFSET.add_size(INDEX_TABLE_SIZE);

// Ring buffer constraints.
pub const DATA_CAPACITY_MAX: MemorySize = MemorySize::new(100 * 1024 * 1024); // 100 MiB
pub const RESULT_MAX_SIZE: MemorySize = MemorySize::new(2_000_000); // 2 MB

struct RingBuffer {
    io: StructIO,
}

impl RingBuffer {
    pub fn new(page_map: PageMap, data_capacity: MemorySize) -> Self {
        let mut io = StructIO::new(page_map);
        io.save_header(&Header::new(data_capacity));

        Self { io }
    }

    pub fn init(page_map: PageMap, data_capacity: MemorySize) -> Self {
        let io = StructIO::new(page_map);
        if io.load_header().magic != *MAGIC {
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
        self.io.load_header().data_capacity.get() as usize
    }

    pub fn used_space(&self) -> usize {
        self.io.load_header().data_size.get() as usize
    }

    pub fn next_id(&self) -> u64 {
        self.io.load_header().next_idx
    }

    pub fn append(&mut self, record: &LogRecord) {
        let added_size = MemorySize::new(record.bytes_len() as u64);
        let capacity = MemorySize::new(self.capacity() as u64);
        if added_size > capacity {
            return;
        }
        // Free space by popping old records if needed.
        while MemorySize::new(self.used_space() as u64) + added_size > capacity {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }

        // Save the record at the tail position.
        let mut h = self.io.load_header();
        self.io.save_record(h.data_tail, record);

        // Update header with new tail position, size and next idx.
        let position = h.data_tail;
        h.data_tail = h.advance_position(position, added_size);
        h.data_size = h.data_size.saturating_add(added_size);
        h.next_idx = record.idx + 1;
        self.io.save_header(&h);

        // Update lookup table after writing the record and updating the header.
        self.update_index(position, record);
    }

    fn pop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.io.load_header();
        let record = self.io.load_record(h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = h.advance_position(h.data_head, removed_size);
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.save_header(&h);
        // No need to update the index here since front entry is never
        // stored in the PageMap but rather computed on table load.
        Some(record)
    }

    fn update_index(&mut self, position: MemoryPosition, record: &LogRecord) {
        // TODO: optimize for loading lots of records in a row.
        let mut index = self.io.load_index();
        index.update(position, record);
        self.io.save_index(index);
    }

    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        let index = self.io.load_index();
        let (start_inclusive, end_inclusive) = match index.bounded_scan_range(filter.clone()) {
            Some(range) => range,
            None => return vec![],
        };

        let header = self.io.load_header();
        let mut records = Vec::new();

        // Walk the coarse range collecting all records in order.
        let mut pos = start_inclusive.position;
        while let Some(record) = self.io.load_record(pos) {
            if record.idx > end_inclusive.idx {
                break; // Reached the end of the range.
            }
            records.push(record.clone());
            pos = header.advance_position(pos, MemorySize::new(record.bytes_len() as u64));
        }

        let records = match filter {
            Some(ref f) => {
                // When a filter is present — keep oldest records (prefix) that match the filter.
                let filtered: Vec<_> = records.into_iter().filter(|r| r.matches(f)).collect();
                take_by_size(&filtered, RESULT_MAX_SIZE, true)
            }
            None => {
                // No filter — return newest records (suffix) up to the size limit.
                take_by_size(&records, RESULT_MAX_SIZE, false)
            }
        };

        records
            .into_iter()
            .map(|r| CanisterLogRecord {
                idx: r.idx,
                timestamp_nanos: r.timestamp,
                content: r.content,
            })
            .collect()
    }
}

/// Keep a prefix or a suffix of `records` whose total serialized size does not
/// exceed `limit` bytes — prefix keeps oldest-first; suffix keeps newest-first.
/// Returns a Vec<LogRecord> in chronological order (oldest-first).
pub fn take_by_size(records: &[LogRecord], limit: MemorySize, take_prefix: bool) -> Vec<LogRecord> {
    let limit = limit.get() as usize;
    if limit == 0 || records.is_empty() {
        return Vec::new();
    }

    let mut total: usize = 0;
    if take_prefix {
        // Find how many from the front fit.
        let mut end: usize = 0;
        for r in records.iter() {
            let sz = r.bytes_len();
            if total + sz > limit {
                break;
            }
            total += sz;
            end += 1;
        }
        records[..end].to_vec()
    } else {
        // Find start index so that records[start..] (the newest records)
        // fit into the limit — walk backward and then clone that tail.
        let mut start: usize = records.len();
        while start > 0 {
            let sz = records[start - 1].bytes_len();
            if total + sz > limit {
                break;
            }
            total += sz;
            start -= 1;
        }
        records[start..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::system_state::log_memory_store::memory::MemorySize;
    use crate::page_map::PageMap;
    use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsRange};

    const TEST_DATA_CAPACITY: MemorySize = MemorySize::new(2_000_000); // 2 MB

    fn log_record(idx: u64, timestamp: u64, message: &str) -> LogRecord {
        LogRecord {
            idx,
            timestamp,
            len: message.len() as u32,
            content: message.as_bytes().to_vec(),
        }
    }

    fn canister_log_record(idx: u64, timestamp: u64, message: &str) -> CanisterLogRecord {
        CanisterLogRecord {
            idx,
            timestamp_nanos: timestamp,
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
        ring_buffer.append(&a);
        ring_buffer.append(&b);

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
        assert_eq!(r0.bytes_len(), record_size);
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
            ring_buffer.append(&record);
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
        ring_buffer.append(&r0);
        ring_buffer.append(&r1);
        ring_buffer.append(&r2);

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
