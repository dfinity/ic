use crate::canister_state::system_state::log_memory_store::{
    header::{HeaderV1, HeaderV1Blob},
    log_record::LogRecord,
    lookup::{LookupEntry, LookupTable},
    memory::{MemoryAddress, MemoryPosition, MemorySize},
};
use crate::page_map::{Buffer, PAGE_SIZE, PageIndex, PageMap};
use ic_sys::PageBytes;
use std::convert::From;

const MAGIC: &[u8; 3] = b"LMS";
const HEADER_OFFSET: MemoryAddress = MemoryAddress::new(0);
const V1_HEADER_SIZE: MemorySize = MemorySize::new(PAGE_SIZE as u64);
const V1_LOOKUP_TABLE_OFFSET: MemoryAddress = HEADER_OFFSET.add_size(V1_HEADER_SIZE);

struct RingBuffer {
    buffer: Buffer,
    lookup_table: LookupTable,
}

impl RingBuffer {
    pub fn new(page_map: PageMap) -> Self {
        let mut ring_buffer = Self {
            buffer: Buffer::new(page_map),
            lookup_table: LookupTable::new(),
        };
        //ring_buffer.init();
        ring_buffer
    }

    pub fn dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        self.buffer.dirty_pages().collect()
    }

    pub fn into_page_map(self) -> PageMap {
        self.buffer.into_page_map()
    }

    pub fn capacity(&self) -> usize {
        self.read_header().data_capacity.get() as usize
    }

    pub fn used_space(&self) -> usize {
        self.read_header().data_size.get() as usize
    }

    pub fn next_id(&self) -> u64 {
        self.read_header().next_idx
    }

    /// Removes the first log record and returns it, or None if the ring buffer is empty.
    pub fn pop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.read_header();
        if h.is_empty() {
            return None;
        }
        let record = self.read_record(h.data_offset + h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        let new_head = (h.data_head + removed_size) % h.data_capacity;
        if h.data_head == h.data_back {
            // If we removed the last available record, move data_back to the new head as well.
            h.data_back = new_head;
        }
        h.data_head = new_head;
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.write_header(&h);
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
        let mut h = self.read_header();
        let tail = h.data_offset + h.data_tail;
        if h.data_tail + added_size < MemoryPosition::new(h.data_capacity.get()) {
            // case 1
            self.write_bytes(tail, &bytes);
        } else {
            // case 2
            let threshold = (h.data_capacity - h.data_tail).as_usize();
            self.write_bytes(tail, &bytes[..threshold]);
            self.write_bytes(h.data_offset, &bytes[threshold..]);
        }
        h.data_back = h.data_tail; // Save current tail as back, last available record.
        h.data_tail = (h.data_tail + added_size) % h.data_capacity;
        h.data_size = h.data_size.saturating_add(added_size);
        h.next_idx = record.idx + 1;
        self.write_header(&h);
    }

    /// Ensures there is enough free space for bytes_len by removing old records.
    fn make_free_space_within_limit(&mut self, bytes_len: MemorySize) {
        while self.used_space() + bytes_len.as_usize() > self.capacity() {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }
    }

    fn write_bytes(&mut self, addr: MemoryAddress, bytes: &[u8]) {
        self.buffer.write(bytes, addr.get());
    }

    /// Generic method to read a vector of bytes from buffer.
    fn read_vec(&self, addr: MemoryAddress, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.buffer.read(&mut bytes, addr.get());
        bytes
    }

    /// Generic method to read fixed-size data from buffer.
    fn read_bytes<const N: usize>(&self, addr: MemoryAddress) -> [u8; N] {
        let mut bytes = [0; N];
        self.buffer.read(&mut bytes, addr.get());
        bytes
    }

    /// Read a u32 from buffer.
    fn read_u32(&self, addr: MemoryAddress) -> u32 {
        u32::from_le_bytes(self.read_bytes(addr))
    }

    /// Read a u64 from buffer.
    fn read_u64(&self, addr: MemoryAddress) -> u64 {
        u64::from_le_bytes(self.read_bytes(addr))
    }

    /// Reads the header from the buffer.
    fn read_header(&self) -> HeaderV1 {
        HeaderV1::from(&HeaderV1Blob::from_bytes(self.read_bytes(HEADER_OFFSET)))
    }

    /// Writes the header to the buffer.
    fn write_header(&mut self, header: &HeaderV1) {
        self.buffer
            .write(HeaderV1Blob::from(header).as_bytes(), HEADER_OFFSET.get());
    }

    /// Retrieves a log record at the given address, if it exists.
    fn read_record(&self, addr: MemoryAddress) -> Option<LogRecord> {
        self.read_header().validate_address(addr)?;
        let idx = self.read_u64(addr);
        let ts_nanos = self.read_u64(addr + MemorySize::new(8));
        let len = self.read_u32(addr + MemorySize::new(16));
        let content = self.read_vec(addr + MemorySize::new(20), len as usize);
        Some(LogRecord {
            idx,
            ts_nanos,
            len,
            content,
        })
    }

    /// Reads only the header of a log record at the given offset, without its content.
    fn read_record_without_content(&self, addr: MemoryAddress) -> Option<LogRecord> {
        self.read_header().validate_address(addr)?;
        let idx = self.read_u64(addr);
        let ts_nanos = self.read_u64(addr + MemorySize::new(8));
        let len = self.read_u32(addr + MemorySize::new(16));
        Some(LogRecord {
            idx,
            ts_nanos,
            len,
            content: Vec::new(),
        })
    }

    fn front_lookup_entry(&self) -> Option<LookupEntry> {
        let header = self.read_header();
        if header.is_empty() {
            return None;
        }
        let record = self.read_record_without_content(header.data_offset + header.data_head)?;
        Some(LookupEntry {
            idx: record.idx,
            ts_nanos: record.ts_nanos,
            position: header.data_head,
        })
    }

    fn back_lookup_entry(&self) -> Option<LookupEntry> {
        let header = self.read_header();
        if header.is_empty() {
            return None;
        }
        let record = self.read_record_without_content(header.data_offset + header.data_back)?;
        Some(LookupEntry {
            idx: record.idx,
            ts_nanos: record.ts_nanos,
            position: header.data_back,
        })
    }

    fn read_lookup_table(&self) -> LookupTable {
        let header = self.read_header();
        let bytes = self.read_vec(
            V1_LOOKUP_TABLE_OFFSET.try_into().unwrap(),
            header.lookup_table_used_bytes(),
        );
        let mut lookup_table = LookupTable::from(&bytes);
        lookup_table.set_front(self.front_lookup_entry().unwrap());
        lookup_table.set_back(self.back_lookup_entry().unwrap());
        lookup_table
    }
}
