use super::byte_rw::{ByteReader, ByteWriter};
use crate::canister_state::system_state::log_memory_store::memory::{
    MemoryAddress, MemoryPosition, MemorySize,
};
use std::convert::From;

#[derive(Debug, PartialEq)]
pub(crate) struct LookupTable {
    front: Option<LookupEntry>,
    back: Option<LookupEntry>,
    entries: Vec<LookupEntry>,
}

impl From<&Vec<u8>> for LookupTable {
    fn from(bytes: &Vec<u8>) -> Self {
        // Each entry is a fixed-size record; anything else is a bug.
        debug_assert_eq!(
            bytes.len() % LOOKUP_ENTRY_SIZE,
            0,
            "lookup table bytes must be a multiple of LOOKUP_ENTRY_SIZE",
        );

        let entry_count = bytes.len() / LOOKUP_ENTRY_SIZE;
        let mut reader = ByteReader::new(bytes);
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            entries.push(LookupEntry {
                idx: reader.read_u64(),
                ts_nanos: reader.read_u64(),
                position: MemoryPosition::new(reader.read_u64()),
            });
        }

        Self {
            front: None,
            back: None,
            entries,
        }
    }
}

impl LookupTable {
    pub fn new() -> Self {
        Self {
            front: None,
            back: None,
            entries: Vec::new(),
        }
    }

    pub fn set_front(&mut self, entry: LookupEntry) {
        self.front = Some(entry);
    }

    pub fn set_back(&mut self, entry: LookupEntry) {
        self.back = Some(entry);
    }

    // pub fn push_back(&mut self, entry: LookupEntry) {
    //     if self.front.is_none() {
    //         self.front = Some(entry);
    //     }
    //     self.back = Some(entry);
    //     let entry_index = entry.position
    //     // TODO: populate entries
    // }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) struct LookupEntry {
    pub idx: u64,
    pub ts_nanos: u64,
    pub position: MemoryPosition,
}
pub(crate) const LOOKUP_ENTRY_SIZE: usize = 24;
const _: () = assert!(std::mem::size_of::<LookupEntry>() == LOOKUP_ENTRY_SIZE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LookupEntryBlob([u8; LOOKUP_ENTRY_SIZE]);

impl LookupEntryBlob {
    /// Creates a new zeroed lookup entry blob.
    pub const fn new() -> Self {
        Self([0; LOOKUP_ENTRY_SIZE])
    }

    /// Returns a reference to the underlying byte array for reading/writing to memory.
    pub fn as_bytes(&self) -> &[u8; LOOKUP_ENTRY_SIZE] {
        &self.0
    }

    /// Returns a mutable reference to the underlying byte array for reading from memory.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; LOOKUP_ENTRY_SIZE] {
        &mut self.0
    }

    /// Creates a LookupEntryBlob from a raw byte array.
    pub fn from_bytes(bytes: [u8; LOOKUP_ENTRY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl Default for LookupEntryBlob {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&LookupEntry> for LookupEntryBlob {
    fn from(entry: &LookupEntry) -> Self {
        let mut blob = [0; LOOKUP_ENTRY_SIZE];
        let mut writer = ByteWriter::new(&mut blob);

        writer.write_u64(entry.idx);
        writer.write_u64(entry.ts_nanos);
        writer.write_u64(entry.position.get() as u64);

        Self(blob)
    }
}

impl From<&LookupEntryBlob> for LookupEntry {
    fn from(blob: &LookupEntryBlob) -> Self {
        let mut reader = ByteReader::new(&blob.0);

        Self {
            idx: reader.read_u64(),
            ts_nanos: reader.read_u64(),
            position: MemoryPosition::new(reader.read_u64()),
        }
    }
}

#[test]
fn test_lookup_slot_serialization() {
    let original = LookupEntry {
        idx: 1,
        ts_nanos: 2,
        position: MemoryPosition::new(3),
    };
    let blob = LookupEntryBlob::from(&original);
    let recovered = LookupEntry::from(&LookupEntryBlob::from_bytes(*blob.as_bytes()));
    assert_eq!(original, recovered);
}
