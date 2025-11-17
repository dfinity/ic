#![allow(dead_code)] // TODO: don't forget to cleanup.

use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::{
    lookup::LOOKUP_ENTRY_SIZE,
    memory::{MemoryAddress, MemoryPosition, MemorySize},
};
use crate::page_map::PAGE_SIZE;

/// Header structure for the log memory store (version 1).
/// This is the in-memory representation of the header.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct HeaderV1 {
    pub magic: [u8; 3],
    pub version: u8,

    // Lookup table metadata.
    pub lookup_table_pages: u16,
    pub lookup_entries_count: u16,

    // Data area metadata.
    pub data_offset: MemoryAddress,
    pub data_capacity: MemorySize,
    pub data_size: MemorySize,
    pub data_head: MemoryPosition,
    pub data_tail: MemoryPosition,
    pub next_idx: u64,
}

const V1_PACKED_HEADER_SIZE: usize = 56;
const _: () = assert!(std::mem::size_of::<HeaderV1>() == V1_PACKED_HEADER_SIZE);

/// A byte array wrapper for serialized header data.
/// This is used for reading from and writing to memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderV1Blob([u8; V1_PACKED_HEADER_SIZE]);

impl HeaderV1Blob {
    /// Creates a new zeroed header blob.
    pub const fn new() -> Self {
        Self([0; V1_PACKED_HEADER_SIZE])
    }

    /// Returns a reference to the underlying byte array for reading/writing to memory.
    pub fn as_bytes(&self) -> &[u8; V1_PACKED_HEADER_SIZE] {
        &self.0
    }

    /// Returns a mutable reference to the underlying byte array for reading from memory.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; V1_PACKED_HEADER_SIZE] {
        &mut self.0
    }

    /// Creates a HeaderV1Blob from a raw byte array.
    pub fn from_bytes(bytes: [u8; V1_PACKED_HEADER_SIZE]) -> Self {
        Self(bytes)
    }
}

impl Default for HeaderV1Blob {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializes a HeaderV1 into a byte blob for disk storage.
impl From<&HeaderV1> for HeaderV1Blob {
    fn from(header: &HeaderV1) -> Self {
        let mut blob = [0u8; V1_PACKED_HEADER_SIZE];
        let mut writer = ByteWriter::new(&mut blob);

        writer.write_bytes(&header.magic);
        writer.write_u8(header.version);
        writer.write_u16(header.lookup_table_pages);
        writer.write_u16(header.lookup_entries_count);
        writer.write_u64(header.data_offset.get() as u64);
        writer.write_u64(header.data_capacity.get());
        writer.write_u64(header.data_size.get());
        writer.write_u64(header.data_head.get());
        writer.write_u64(header.data_tail.get());
        writer.write_u64(header.next_idx);

        Self(blob)
    }
}

/// Deserializes a HeaderV1 from a byte blob read from disk.
impl From<&HeaderV1Blob> for HeaderV1 {
    fn from(blob: &HeaderV1Blob) -> Self {
        let mut reader = ByteReader::new(&blob.0);

        Self {
            magic: reader.read_bytes(),
            version: reader.read_u8(),
            lookup_table_pages: reader.read_u16(),
            lookup_entries_count: reader.read_u16(),
            data_offset: reader.read_u64().into(),
            data_capacity: reader.read_u64().into(),
            data_size: reader.read_u64().into(),
            data_head: reader.read_u64().into(),
            data_tail: reader.read_u64().into(),
            next_idx: reader.read_u64(),
        }
    }
}

impl HeaderV1 {
    pub fn is_empty(&self) -> bool {
        self.data_size == MemorySize::new(0)
    }

    pub fn advance_position(&self, pos: MemoryPosition, size: MemorySize) -> MemoryPosition {
        (pos + size) % self.data_capacity
    }

    pub fn validate_address(&self, addr: MemoryAddress) -> Option<()> {
        if self.is_empty() {
            return None;
        }

        let is_within = |x: MemoryAddress, a: MemoryAddress, b: MemoryAddress| a <= x && x < b;

        let head = self.data_offset + self.data_head;
        let tail = self.data_offset + self.data_tail;
        let is_valid = if !self.is_wrapped() {
            is_within(addr, head, tail) // [head, tail)
        } else {
            let start = self.data_offset;
            let end = self.data_offset + self.data_capacity;
            is_within(addr, head, end) // [head, end)
                || is_within(addr, start, tail) // or [start, tail)
        };
        is_valid.then_some(())
    }

    /// Checks if the ring buffer is currently wrapped around.
    fn is_wrapped(&self) -> bool {
        // When head == tail, the buffer is either empty or full.
        if self.data_tail == self.data_head {
            return self.data_size > MemorySize::new(0);
        }
        self.data_tail < self.data_head // Wrapped if tail is before head.
    }

    /// Returns the size in bytes of the used portion of the lookup table.
    /// This is bounded by the number of entries that fit into the allocated pages.
    pub fn lookup_table_used_bytes(&self) -> usize {
        let allocated_bytes = self.lookup_table_pages as usize * PAGE_SIZE;
        let capacity_entries = allocated_bytes / LOOKUP_ENTRY_SIZE;
        let used_entries = usize::min(self.lookup_entries_count as usize, capacity_entries);

        used_entries * LOOKUP_ENTRY_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_v1_roundtrip_serialization() {
        let original = HeaderV1 {
            magic: *b"LMS",
            version: 1,
            lookup_table_pages: 2,
            lookup_entries_count: 3,
            data_offset: MemoryAddress::new(4),
            data_capacity: MemorySize::new(5),
            data_size: MemorySize::new(6),
            data_head: MemoryPosition::new(7),
            data_tail: MemoryPosition::new(8),
            next_idx: 9,
        };

        let blob = HeaderV1Blob::from(&original);
        let recovered = HeaderV1::from(&HeaderV1Blob::from_bytes(*blob.as_bytes()));

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_header_v1_blob_size() {
        assert_eq!(std::mem::size_of::<HeaderV1Blob>(), V1_PACKED_HEADER_SIZE);
    }

    #[test]
    fn test_header_v1_blob_default() {
        let blob = HeaderV1Blob::default();
        assert_eq!(blob.as_bytes(), &[0u8; V1_PACKED_HEADER_SIZE]);
    }
}
