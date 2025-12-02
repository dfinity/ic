use crate::canister_state::system_state::log_memory_store::{
    header::Header,
    index_table::{IndexEntry, IndexTable},
    log_record::LogRecord,
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    ring_buffer::{DATA_REGION_OFFSET, HEADER_OFFSET, INDEX_TABLE_OFFSET, RESULT_MAX_SIZE},
};
use crate::page_map::{Buffer, PageMap};
use std::cell::RefCell;

pub(super) struct StructIO {
    buffer: Buffer,
    cache_header: RefCell<Option<Header>>,
}

impl StructIO {
    pub fn new(page_map: PageMap) -> Self {
        Self {
            buffer: Buffer::new(page_map),
            cache_header: RefCell::new(None),
        }
    }

    pub fn to_page_map(&self) -> PageMap {
        self.buffer.to_page_map()
    }

    pub fn load_header(&self) -> Header {
        if let Some(cached_header) = self.cache_header.borrow().as_ref() {
            return cached_header.clone();
        }
        let (magic, addr) = self.read_raw_bytes::<3>(HEADER_OFFSET);
        let (version, addr) = self.read_raw_u8(addr);
        let (index_table_pages, addr) = self.read_raw_u16(addr);
        let (index_entries_count, addr) = self.read_raw_u16(addr);
        let (data_offset, addr) = self.read_raw_u64(addr);
        let (data_capacity, addr) = self.read_raw_u64(addr);
        let (data_size, addr) = self.read_raw_u64(addr);
        let (data_head, addr) = self.read_raw_u64(addr);
        let (data_tail, addr) = self.read_raw_u64(addr);
        let (next_idx, addr) = self.read_raw_u64(addr);
        let (max_timestamp, _addr) = self.read_raw_u64(addr);
        let header = Header {
            magic,
            version,
            index_table_pages,
            index_entries_count,
            data_offset: MemoryAddress::new(data_offset),
            data_capacity: MemorySize::new(data_capacity),
            data_size: MemorySize::new(data_size),
            data_head: MemoryPosition::new(data_head),
            data_tail: MemoryPosition::new(data_tail),
            next_idx,
            max_timestamp,
        };
        self.cache_header.replace(Some(header.clone()));
        header
    }

    pub fn save_header(&mut self, header: &Header) {
        let mut addr = HEADER_OFFSET;
        addr = self.write_raw_bytes(addr, &header.magic);
        addr = self.write_raw_u8(addr, header.version);
        addr = self.write_raw_u16(addr, header.index_table_pages);
        addr = self.write_raw_u16(addr, header.index_entries_count);
        addr = self.write_raw_u64(addr, header.data_offset.get());
        addr = self.write_raw_u64(addr, header.data_capacity.get());
        addr = self.write_raw_u64(addr, header.data_size.get());
        addr = self.write_raw_u64(addr, header.data_head.get());
        addr = self.write_raw_u64(addr, header.data_tail.get());
        addr = self.write_raw_u64(addr, header.next_idx);
        _ = self.write_raw_u64(addr, header.max_timestamp);
        self.cache_header.replace(Some(header));
    }

    pub fn load_index_table(&self) -> IndexTable {
        let h = self.load_header();
        let pos = h.data_head;
        let front = self
            .load_record_without_content(pos)
            .map(|record| IndexEntry::new(pos, &record));
        let entries = if h.index_entries_count == 0 {
            vec![]
        } else {
            let mut entries = Vec::with_capacity(h.index_entries_count as usize);
            let mut addr = INDEX_TABLE_OFFSET;
            for _ in 0..h.index_entries_count {
                let (entry, next_addr) = self.read_index_entry(addr);
                entries.push(entry);
                addr = next_addr;
            }
            entries
        };
        IndexTable::new(
            front,
            h.data_capacity,
            h.index_table_pages,
            RESULT_MAX_SIZE,
            entries,
        )
    }

    /// Save index table to the memory store.
    /// IMPORTANT: the caller must ensure that the header
    /// is created and up-to-date.
    pub fn save_index_table(&mut self, index: &IndexTable) {
        // Save entries.
        let mut addr = INDEX_TABLE_OFFSET;
        for entry in index.raw_entries() {
            addr = self.write_index_entry(addr, entry)
        }
        // Update header with the entries count.
        let mut header = self.load_header();
        header.index_entries_count = index.raw_entries().len() as u16;
        self.save_header(&header);
    }

    fn read_index_entry(&self, addr: MemoryAddress) -> (IndexEntry, MemoryAddress) {
        let (position, addr) = self.read_raw_u64(addr);
        let (idx, addr) = self.read_raw_u64(addr);
        let (timestamp, addr) = self.read_raw_u64(addr);
        let (bytes_len, addr) = self.read_raw_u32(addr);
        (
            IndexEntry {
                position: MemoryPosition::new(position),
                idx,
                timestamp,
                bytes_len,
            },
            addr,
        )
    }

    fn write_index_entry(&mut self, addr: MemoryAddress, entry: &IndexEntry) -> MemoryAddress {
        let addr = self.write_raw_u64(addr, entry.position.get());
        let addr = self.write_raw_u64(addr, entry.idx);
        let addr = self.write_raw_u64(addr, entry.timestamp);
        self.write_raw_u32(addr, entry.bytes_len)
    }

    fn load_record_header(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u64, u64, u32, MemoryPosition) {
        let (idx, position) = self.read_wrapped_u64(position, offset, capacity);
        let (timestamp, position) = self.read_wrapped_u64(position, offset, capacity);
        let (len, position) = self.read_wrapped_u32(position, offset, capacity);
        (idx, timestamp, len, position)
    }

    pub fn load_record_without_content(&self, position: MemoryPosition) -> Option<LogRecord> {
        let h = self.load_header();
        if !h.is_alive(position) {
            return None;
        }
        let (offset, capacity) = (DATA_REGION_OFFSET, h.data_capacity);
        let (idx, timestamp, len, _position) = self.load_record_header(position, offset, capacity);
        Some(LogRecord {
            idx,
            timestamp,
            len,
            content: vec![], // Content is not loaded here.
        })
    }

    pub fn load_record(&self, position: MemoryPosition) -> Option<LogRecord> {
        let h = self.load_header();
        if !h.is_alive(position) {
            return None;
        }
        let (offset, capacity) = (DATA_REGION_OFFSET, h.data_capacity);
        let (idx, timestamp, len, position) = self.load_record_header(position, offset, capacity);
        let (content, _position) =
            self.read_wrapped_vec(position, MemorySize::new(len as u64), offset, capacity);
        Some(LogRecord {
            idx,
            timestamp,
            len,
            content,
        })
    }

    pub fn save_record(&mut self, position: MemoryPosition, record: &LogRecord) {
        let (offset, capacity) = (DATA_REGION_OFFSET, self.load_header().data_capacity);
        let position = self.write_wrapped_u64(position, record.idx, offset, capacity);
        let position = self.write_wrapped_u64(position, record.timestamp, offset, capacity);
        let position = self.write_wrapped_u32(position, record.len, offset, capacity);
        _ = self.write_wrapped_bytes(position, &record.content, offset, capacity);
    }

    fn read_raw_vec(&self, address: MemoryAddress, len: MemorySize) -> (Vec<u8>, MemoryAddress) {
        let mut bytes = vec![0; len.get() as usize];
        self.buffer.read(&mut bytes, address.get() as usize);
        (bytes, address + len)
    }

    fn read_raw_bytes<const N: usize>(&self, address: MemoryAddress) -> ([u8; N], MemoryAddress) {
        let mut bytes = [0; N];
        self.buffer.read(&mut bytes, address.get() as usize);
        (bytes, address + MemorySize::new(N as u64))
    }

    fn write_raw_bytes(&mut self, address: MemoryAddress, bytes: &[u8]) -> MemoryAddress {
        self.buffer.write(bytes, address.get() as usize);
        address + MemorySize::new(bytes.len() as u64)
    }

    fn remaining(position: MemoryPosition, capacity: MemorySize) -> MemorySize {
        if position < MemoryPosition::new(capacity.get()) {
            capacity - position
        } else {
            MemorySize::new(0)
        }
    }

    fn read_wrapped_vec(
        &self,
        position: MemoryPosition,
        len: MemorySize,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (Vec<u8>, MemoryPosition) {
        let remaining = Self::remaining(position, capacity);
        let bytes = if len <= remaining {
            // No wrap.
            let (bytes, _addr) = self.read_raw_vec(offset + position, len);
            bytes
        } else {
            // Wraps around.
            let (mut bytes, _addr) = self.read_raw_vec(offset + position, remaining);
            let second_part_size = len - remaining;
            let (mut second_part, _addr) = self.read_raw_vec(offset, second_part_size);
            bytes.append(&mut second_part);
            bytes
        };
        (bytes, (position + len) % capacity)
    }

    fn read_wrapped_bytes<const N: usize>(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> ([u8; N], MemoryPosition) {
        let mut result = [0u8; N];
        let len = MemorySize::new(N as u64);
        let remaining = Self::remaining(position, capacity);
        if len <= remaining {
            // No wrap.
            let (bytes, _addr) = self.read_raw_vec(offset + position, len);
            result.copy_from_slice(&bytes);
        } else {
            // Wraps around.
            let first_part_size = remaining.get() as usize;
            let (first_part, _addr) = self.read_raw_vec(offset + position, remaining);
            result[..first_part_size].copy_from_slice(&first_part);
            let (second_part, _addr) = self.read_raw_vec(offset, len - remaining);
            result[first_part_size..].copy_from_slice(&second_part);
        }
        (result, (position + len) % capacity)
    }

    fn write_wrapped_bytes(
        &mut self,
        position: MemoryPosition,
        bytes: &[u8],
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        let remaining = Self::remaining(position, capacity);
        let len = MemorySize::new(bytes.len() as u64);
        if len <= remaining {
            // No wrap.
            self.write_raw_bytes(offset + position, bytes);
        } else {
            // Wrap around.
            let split = remaining.get() as usize;
            self.write_raw_bytes(offset + position, &bytes[..split]);
            self.write_raw_bytes(offset, &bytes[split..]);
        }
        (position + len) % capacity
    }

    fn read_raw_u8(&self, address: MemoryAddress) -> (u8, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<1>(address);
        (bytes[0], addr)
    }

    fn read_raw_u16(&self, address: MemoryAddress) -> (u16, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<2>(address);
        (u16::from_le_bytes(bytes), addr)
    }

    fn read_raw_u32(&self, address: MemoryAddress) -> (u32, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<4>(address);
        (u32::from_le_bytes(bytes), addr)
    }

    fn read_raw_u64(&self, address: MemoryAddress) -> (u64, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<8>(address);
        (u64::from_le_bytes(bytes), addr)
    }

    fn write_raw_u8(&mut self, address: MemoryAddress, value: u8) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u16(&mut self, address: MemoryAddress, value: u16) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u32(&mut self, address: MemoryAddress, value: u32) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u64(&mut self, address: MemoryAddress, value: u64) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn read_wrapped_u32(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u32, MemoryPosition) {
        let (bytes, position) = self.read_wrapped_bytes::<4>(position, offset, capacity);
        (u32::from_le_bytes(bytes), position)
    }

    fn read_wrapped_u64(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u64, MemoryPosition) {
        let (bytes, position) = self.read_wrapped_bytes::<8>(position, offset, capacity);
        (u64::from_le_bytes(bytes), position)
    }

    fn write_wrapped_u32(
        &mut self,
        position: MemoryPosition,
        value: u32,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        self.write_wrapped_bytes(position, &value.to_le_bytes(), offset, capacity)
    }

    fn write_wrapped_u64(
        &mut self,
        position: MemoryPosition,
        value: u64,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        self.write_wrapped_bytes(position, &value.to_le_bytes(), offset, capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip_serialization() {
        let original = Header {
            magic: *b"abc",
            version: 1,
            index_table_pages: 2,
            index_entries_count: 3,
            data_offset: MemoryAddress::new(4),
            data_capacity: MemorySize::new(5),
            data_size: MemorySize::new(6),
            data_head: MemoryPosition::new(7),
            data_tail: MemoryPosition::new(8),
            next_idx: 9,
            max_timestamp: 10,
        };

        let mut io = StructIO::new(PageMap::new_for_testing());
        io.save_header(&original);
        let loaded = io.load_header();

        assert_eq!(original, loaded);
    }

    #[test]
    fn test_index_default_load() {
        let mut io = StructIO::new(PageMap::new_for_testing());
        let data_capacity = MemorySize::new(10_000_000);
        io.save_header(&Header::new(data_capacity));
        let loaded_index = io.load_index_table();
        let loaded = loaded_index.raw_entries();

        // For 10 MB data capacity, 28 bytes per entry = 146 entries
        assert_eq!(loaded.len(), 146);
        // All loaded entries are invalid.
        for entry in loaded {
            assert!(!entry.is_valid());
        }
    }

    #[test]
    fn test_index_roundtrip_serialization() {
        let original = vec![
            IndexEntry {
                position: MemoryPosition::new(10),
                idx: 1,
                timestamp: 100,
                bytes_len: 12,
            },
            IndexEntry {
                position: MemoryPosition::new(20),
                idx: 2,
                timestamp: 200,
                bytes_len: 34,
            },
        ];

        let mut io = StructIO::new(PageMap::new_for_testing());
        let data_capacity = MemorySize::new(10_000_000);
        io.save_header(&Header::new(data_capacity));
        io.save_index_table(&IndexTable::new(
            None,
            data_capacity,
            1,
            RESULT_MAX_SIZE,
            original.clone(),
        ));
        let loaded_index = io.load_index_table();
        let loaded = loaded_index.raw_entries();

        assert_eq!(loaded.len(), original.len());
        for (a, b) in original.iter().zip(loaded.iter()) {
            assert_eq!(a, b)
        }
    }

    #[test]
    fn test_record_roundtrip_serialization() {
        let data_capacity = MemorySize::new(1_000_000);
        let no_wrap_position = MemoryPosition::new(100);
        let wrap_position = MemoryPosition::new(1_000_000 - 2);
        for position in [no_wrap_position, wrap_position] {
            let content = b"hello world".to_vec();
            let original = LogRecord {
                idx: 42,
                timestamp: 1_234_567,
                len: content.len() as u32,
                content: content.clone(),
            };

            let mut io = StructIO::new(PageMap::new_for_testing());
            let mut header = Header::new(data_capacity);
            header.data_head = position;
            let size = MemorySize::new(original.bytes_len() as u64);
            header.data_tail = header.advance_position(position, size);
            header.data_size = size;
            io.save_header(&header);

            io.save_record(position, &original);
            let loaded = io.load_record(position).expect("record should be present");

            assert_eq!(original, loaded);
        }
    }
}
