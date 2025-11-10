use crate::canister_state::system_state::log_memory_store::{
    header::HeaderV1,
    log_record::LogRecord,
    lookup::LookupTable,
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    struct_io::StructIO,
};
use crate::page_map::{PAGE_SIZE, PageIndex, PageMap};
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
        let header = HeaderV1 {
            magic: *MAGIC,
            version: 1,
            lookup_table_pages: LOOKUP_TABLE_PAGES,
            lookup_entries_count: 0,
            data_offset: V1_LOOKUP_TABLE_OFFSET,
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
