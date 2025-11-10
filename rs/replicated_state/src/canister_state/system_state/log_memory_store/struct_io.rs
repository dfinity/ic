use crate::canister_state::system_state::log_memory_store::{
    header::{HeaderV1, HeaderV1Blob},
    log_record::LogRecord,
    lookup::{LookupEntry, LookupTable, to_entries},
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    ring_buffer::{HEADER_OFFSET, V1_LOOKUP_TABLE_OFFSET},
};
use crate::page_map::{Buffer, PageIndex, PageMap};
use ic_sys::PageBytes;
use std::convert::From;

pub(crate) struct StructIO(Buffer);

impl StructIO {
    pub fn new(page_map: PageMap) -> Self {
        Self(Buffer::new(page_map))
    }

    pub fn dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        self.0.dirty_pages().collect()
    }

    pub fn into_page_map(self) -> PageMap {
        self.0.into_page_map()
    }

    /// Write bytes into buffer.
    pub fn write_bytes(&mut self, addr: MemoryAddress, bytes: &[u8]) {
        self.0.write(bytes, addr.get());
    }

    /// Read a vector of bytes from buffer.
    pub fn read_vec(&self, addr: MemoryAddress, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.0.read(&mut bytes, addr.get());
        bytes
    }

    /// Read fixed-size data from buffer.
    pub fn read_bytes<const N: usize>(&self, addr: MemoryAddress) -> [u8; N] {
        let mut bytes = [0; N];
        self.0.read(&mut bytes, addr.get());
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

    /// Writes the header to the buffer.
    pub fn write_header(&mut self, header: &HeaderV1) {
        self.0
            .write(HeaderV1Blob::from(header).as_bytes(), HEADER_OFFSET.get());
    }

    /// Reads the header from the buffer.
    pub fn read_header(&self) -> HeaderV1 {
        HeaderV1::from(&HeaderV1Blob::from_bytes(self.read_bytes(HEADER_OFFSET)))
    }

    pub fn read_lookup_table(&self) -> LookupTable {
        let h = self.read_header();
        let bytes = self.read_vec(V1_LOOKUP_TABLE_OFFSET, h.lookup_table_used_bytes());
        let mut lookup_table = LookupTable::new(to_entries(&bytes));
        lookup_table.set_front(self.read_lookup_entry(h.data_head));
        lookup_table
    }

    pub fn write_lookup_table(&mut self, lookup_table: &LookupTable) {
        let bytes = Vec::from(lookup_table);
        self.write_bytes(V1_LOOKUP_TABLE_OFFSET, &bytes);
    }

    /// Retrieves a log record at the given address, if it exists.
    pub fn read_record(&self, addr: MemoryAddress) -> Option<LogRecord> {
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

    fn read_lookup_entry(&self, position: MemoryPosition) -> Option<LookupEntry> {
        let h = self.read_header();
        if h.is_empty() {
            return None;
        }
        let record = self.read_record_without_content(h.data_offset + position)?;
        Some(LookupEntry {
            idx: record.idx,
            ts_nanos: record.ts_nanos,
            position,
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
}
