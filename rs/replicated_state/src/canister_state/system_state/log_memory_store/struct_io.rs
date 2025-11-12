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

struct MemoryChunk {
    offset: MemoryAddress,
    capacity: MemorySize,
}

pub(crate) struct StructIO {
    buffer: Buffer,
}

impl StructIO {
    pub fn new(page_map: PageMap) -> Self {
        Self {
            buffer: Buffer::new(page_map),
        }
    }

    pub fn dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        self.buffer.dirty_pages().collect()
    }

    pub fn into_page_map(self) -> PageMap {
        self.buffer.into_page_map()
    }

    fn write_bytes(&mut self, addr: MemoryAddress, bytes: &[u8]) {
        self.buffer.write(bytes, addr.get());
    }

    fn read_vec(&self, addr: MemoryAddress, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.buffer.read(&mut bytes, addr.get());
        bytes
    }

    fn read_bytes<const N: usize>(&self, addr: MemoryAddress) -> [u8; N] {
        let mut bytes = [0; N];
        self.buffer.read(&mut bytes, addr.get());
        bytes
    }

    /// Writes the header to the buffer.
    pub fn write_header(&mut self, header: &HeaderV1) {
        self.buffer
            .write(HeaderV1Blob::from(header).as_bytes(), HEADER_OFFSET.get());
    }

    /// Reads the header from the buffer.
    pub fn read_header(&self) -> HeaderV1 {
        HeaderV1::from(&HeaderV1Blob::from_bytes(self.read_bytes(HEADER_OFFSET)))
    }

    pub fn write_lookup_table(&mut self, lookup_table: &LookupTable) {
        // Serialize lookup table buckets.
        self.write_bytes(V1_LOOKUP_TABLE_OFFSET, &lookup_table.serialized_buckets());
        // Update header with the lookup buckets count.
        let mut h = self.read_header();
        h.lookup_entries_count = lookup_table.buckets_len();
        self.write_header(&h);
    }

    pub fn read_lookup_table(&self) -> LookupTable {
        let h = self.read_header();
        let front = self.read_lookup_entry(h.data_head);
        if h.lookup_table_used_bytes() == 0 {
            LookupTable::new(front, h.lookup_table_pages, h.data_capacity, &[])
        } else {
            let bytes = self.read_vec(V1_LOOKUP_TABLE_OFFSET, h.lookup_table_used_bytes());
            LookupTable::new(front, h.lookup_table_pages, h.data_capacity, &bytes)
        }
    }

    fn read_lookup_entry(&self, position: MemoryPosition) -> Option<LookupEntry> {
        let record = self.read_record_without_content(position)?;
        Some(LookupEntry::new(&record, position))
    }

    fn write_data_bytes(&mut self, pos: MemoryPosition, bytes: &[u8], memory: &MemoryChunk) {
        let remaining_size = memory.capacity - pos;
        if MemorySize::new(bytes.len() as u64) <= remaining_size {
            // No wrap.
            self.write_bytes(memory.offset + pos, bytes);
        } else {
            // Wrap around.
            let split = remaining_size.get() as usize;
            self.write_bytes(memory.offset + pos, &bytes[..split]);
            self.write_bytes(memory.offset, &bytes[split..]);
        }
    }

    fn read_data_vec(&self, pos: MemoryPosition, len: usize, memory: &MemoryChunk) -> Vec<u8> {
        let remaining_size = memory.capacity - pos;
        if MemorySize::new(len as u64) <= remaining_size {
            // No wrap.
            self.read_vec(memory.offset + pos, len)
        } else {
            // Wrap around.
            let mut content = Vec::with_capacity(len);
            let first_part_size = remaining_size.get() as usize;
            content.extend_from_slice(&self.read_vec(memory.offset + pos, first_part_size));
            let second_part_size = len - first_part_size;
            content.extend_from_slice(&self.read_vec(memory.offset, second_part_size));
            content
        }
    }

    fn read_data_bytes<const N: usize>(
        &self,
        pos: MemoryPosition,
        memory: &MemoryChunk,
    ) -> [u8; N] {
        let remaining_size = memory.capacity - pos;
        if MemorySize::new(N as u64) <= remaining_size {
            // No wrap.
            self.read_bytes(memory.offset + pos)
        } else {
            // Wrap around.
            let mut bytes = [0; N];
            let split = remaining_size.get() as usize;
            self.buffer
                .read(&mut bytes[..split], (memory.offset + pos).get());
            self.buffer.read(&mut bytes[split..], memory.offset.get());
            bytes
        }
    }

    fn read_data_u64(&self, pos: MemoryPosition, memory: &MemoryChunk) -> u64 {
        u64::from_le_bytes(self.read_data_bytes::<8>(pos, memory))
    }

    fn read_data_u32(&self, pos: MemoryPosition, memory: &MemoryChunk) -> u32 {
        u32::from_le_bytes(self.read_data_bytes::<4>(pos, memory))
    }

    pub fn write_record(&mut self, record: &LogRecord, position: MemoryPosition) {
        let bytes: Vec<u8> = record.into();
        debug_assert_eq!(bytes.len(), record.bytes_len());
        let h = self.read_header();
        let memory = MemoryChunk {
            offset: h.data_offset,
            capacity: h.data_capacity,
        };
        self.write_data_bytes(position, &bytes, &memory);
    }

    /// Retrieves a log record at the given address, if it exists.
    pub fn read_record(&self, mut pos: MemoryPosition) -> Option<LogRecord> {
        let h = self.read_header();
        h.validate_address(h.data_offset + pos)?;
        let memory = MemoryChunk {
            offset: h.data_offset,
            capacity: h.data_capacity,
        };

        let idx = self.read_data_u64(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(8));

        let ts_nanos = self.read_data_u64(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(8));

        let len = self.read_data_u32(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(4));

        let content = self.read_data_vec(pos, len as usize, &memory);

        Some(LogRecord {
            idx,
            ts_nanos,
            len,
            content,
        })
    }

    /// Reads only the header of a log record at the given offset, without its content.
    fn read_record_without_content(&self, mut pos: MemoryPosition) -> Option<LogRecord> {
        let h = self.read_header();
        h.validate_address(h.data_offset + pos)?;
        let memory = MemoryChunk {
            offset: h.data_offset,
            capacity: h.data_capacity,
        };

        let idx = self.read_data_u64(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(8));

        let ts_nanos = self.read_data_u64(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(8));

        let len = self.read_data_u32(pos, &memory);
        pos = h.advance_position(pos, MemorySize::new(4));

        Some(LogRecord {
            idx,
            ts_nanos,
            len,
            content: Vec::new(),
        })
    }
}
