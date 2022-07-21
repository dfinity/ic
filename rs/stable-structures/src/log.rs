//! This module implements append-only list data structure, also known as log.
//! It supports arbitrary-sized entries and constant-time access to any entry.
//! The trade-off is that the maximum number of entries must be known in advance.
//!
//! # V1 layout
//!
//! ```text
//! ---------------------------------------- <- Address 0
//! Magic "SLG"             ↕ 3 bytes
//! ----------------------------------------
//! Layout version          ↕ 1 byte
//! ----------------------------------------
//! Max entries = N         ↕ 4 bytes
//! ----------------------------------------
//! Reserved space          ↕ 20 bytes
//! ---------------------------------------- <- Index offset
//! Number of entries = L   ↕ 4 bytes
//! ---------------------------------------- <- Address 32
//! E_0                     ↕ 8 bytes         
//! ----------------------------------------
//! E_0 + E_1               ↕ 8 bytes
//! ----------------------------------------
//! ...
//! ----------------------------------------
//! E_0 + ... + E_(L-1)     ↕ 8 bytes
//! ----------------------------------------
//! Unused index entries    ↕ 8×(N-L) bytes
//! ---------------------------------------- <- Entries offset
//! Entry 0 bytes           ↕ E_0 bytes
//! ----------------------------------------
//! Entry 1 bytes           ↕ E_1 bytes
//! ----------------------------------------
//! ...
//! ----------------------------------------
//! Entry (L-1) bytes       ↕ E_(L-1) bytes
//! ----------------------------------------
//! Unallocated space
//! ```
use crate::{
    read_u32, read_u64, safe_write, types::Address, write_u32, write_u64, GrowFailed, Memory,
};
#[cfg(test)]
mod tests;

/// The magic number: Stable LoG.
const MAGIC: &[u8; 3] = b"SLG";

/// The current version of the layout.
const LAYOUT_VERSION: u8 = 1;

/// The size of the V1 layout header.
const HEADER_V1_SIZE: u64 = 8;

/// The number of header bytes reserved for future extensions.
const RESERVED_SIZE: u64 = 20;

struct HeaderV1 {
    magic: [u8; 3],
    version: u8,
    max_entries: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitError {
    IncompatibleVersion {
        last_supported_version: u8,
        decoded_version: u8,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    IndexFull { max_entries: u32 },
    GrowFailed { current_size: u64, delta: u64 },
}

impl From<GrowFailed> for WriteError {
    fn from(
        GrowFailed {
            current_size,
            delta,
        }: GrowFailed,
    ) -> Self {
        Self::GrowFailed {
            current_size,
            delta,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NoSuchEntry;

/// Append-only list of variable-size entries stored in memory with constant-time access to all
/// records. The max number of entries must be known in advance.
///
/// NB. think carefully when setting the max_entries parameter in `new` and `init` functions.
/// The log structure pre-allocates an index table that needs 8 bytes for each entry.
/// Setting `max_entries` to 1_000_000 entries will consume ~8MiB of memory.
/// Setting `max_entries` to [u32::MAX] will exhaust the memory limit and make the log unusable.
pub struct Log<M: Memory> {
    max_entries: u32,
    index_offset: u64,
    entries_offset: u64,
    memory: M,
}

/// The total length of the log index in bytes.
fn index_len(max_entries: u32) -> u64 {
    // 4 bytes for the number of entries and 8 bytes per entry for offsets.
    // See the layout picture above for more details.
    std::mem::size_of::<u32>() as u64 + (max_entries as u64) * std::mem::size_of::<u64>() as u64
}

impl<M: Memory> Log<M> {
    /// Creates a new empty stable log backed by the memory, overwriting the previous contents of
    /// memory.
    pub fn new(memory: M, max_entries: u32) -> Self {
        Self::write_header(
            &memory,
            &HeaderV1 {
                magic: *MAGIC,
                version: LAYOUT_VERSION,
                max_entries,
            },
        );

        let index_offset = HEADER_V1_SIZE + RESERVED_SIZE;

        // Write the number of entries
        crate::write_u32(&memory, Address::from(index_offset), 0);

        Self {
            max_entries,
            index_offset,
            entries_offset: index_offset + index_len(max_entries),
            memory,
        }
    }

    /// Initializes the log based on the contents of the memory.
    /// If the memory already contains a stable log, this function recovers it from the stable
    /// memory. Otherwise, this function allocates a new empty log in the memory.
    pub fn init(memory: M, max_entries: u32) -> Result<Self, InitError> {
        if memory.size() == 0 {
            return Ok(Self::new(memory, max_entries));
        }

        let header = Self::read_header(&memory);
        if &header.magic != MAGIC {
            return Ok(Self::new(memory, max_entries));
        }

        if header.version != LAYOUT_VERSION {
            return Err(InitError::IncompatibleVersion {
                last_supported_version: LAYOUT_VERSION,
                decoded_version: header.version,
            });
        }

        let max_entries = header.max_entries;
        let index_offset = HEADER_V1_SIZE + RESERVED_SIZE;

        #[cfg(debug_assertions)]
        {
            assert_eq!(Ok(()), Self::validate_v1_index(&memory, max_entries));
        }

        Ok(Self {
            max_entries,
            index_offset,
            entries_offset: index_offset + index_len(max_entries),
            memory,
        })
    }

    /// Writes the stable log header to the memory.
    fn write_header(memory: &M, header: &HeaderV1) {
        if memory.size() < 1 {
            assert!(
                memory.grow(1) != -1,
                "failed to allocate the first memory page"
            );
        }
        memory.write(0, &header.magic);
        memory.write(3, &[header.version]);
        crate::write_u32(memory, Address::from(4), header.max_entries);
    }

    /// Reads the stable log header from the memory.
    /// PRECONDITION: memory.size() > 0
    fn read_header(memory: &M) -> HeaderV1 {
        let mut magic = [0u8; 3];
        let mut version = [0u8; 1];
        memory.read(0, &mut magic);
        memory.read(3, &mut version);
        let max_entries = read_u32(memory, Address::from(4));
        HeaderV1 {
            magic,
            version: version[0],
            max_entries,
        }
    }

    #[cfg(debug_assertions)]
    fn validate_v1_index(memory: &M, max_entries: u32) -> Result<(), String> {
        let index_offset = HEADER_V1_SIZE + RESERVED_SIZE;

        let num_entries = read_u32(memory, Address::from(index_offset));
        if num_entries > max_entries {
            return Err(format!(
                "the number of entries {} exceeds max_entries {}",
                num_entries, max_entries
            ));
        }

        if num_entries == 0 {
            return Ok(());
        }

        // Check that the index entries are non-decreasing.
        let mut prev_entry = read_u64(memory, Address::from(index_offset + 4));
        for i in 1..(num_entries as u64) {
            let entry = read_u64(memory, Address::from(index_offset + 4 + i * 8));
            if entry < prev_entry {
                return Err(format!(
                    "invalid entry I[{}]: {} < {}",
                    i, entry, prev_entry
                ));
            }
            prev_entry = entry;
        }
        Ok(())
    }

    /// Returns the underlying memory of the log.
    pub fn forget(self) -> M {
        self.memory
    }

    /// Returns true iff this log does not have any entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total size of all logged entries in bytes.
    pub fn size_bytes(&self) -> usize {
        let num_entries = read_u32(&self.memory, Address::from(self.index_offset));
        if num_entries == 0 {
            0
        } else {
            read_u64(&self.memory, self.index_entry_offset(num_entries - 1)) as usize
        }
    }

    /// Returns the number of entries in the log.
    pub fn len(&self) -> usize {
        read_u32(&self.memory, Address::from(self.index_offset)) as usize
    }

    /// Returns the max number of entries this log can hold.
    pub fn max_len(&self) -> usize {
        self.max_entries as usize
    }

    /// Returns the entry at the specified index.
    /// Returns None if the entry does not exist.
    pub fn get(&self, idx: usize) -> Option<Vec<u8>> {
        let mut buf = vec![];
        self.read_entry(idx, &mut buf).ok().map(|_| buf)
    }

    /// Reads the contents of the entry with the specified index into
    /// a byte vector.
    ///
    /// NOTE: if the entry exists, this function resizes `buf` to match the entry size.
    ///
    /// NOTE: this function returns a Result to make the compiler emit a warning if the caller
    /// ignores the result.
    pub fn read_entry(&self, idx: usize, buf: &mut Vec<u8>) -> Result<(), NoSuchEntry> {
        let (offset, len) = self.entry_meta(idx).ok_or(NoSuchEntry)?;
        buf.resize(len, 0);
        self.memory.read((self.entries_offset + offset) as u64, buf);
        Ok(())
    }

    /// Appends a new entry to the log.
    /// If successful, returns the index of the entry.
    ///
    /// POST-CONDITION: Ok(idx) = log.append(E) ⇒ log.get(idx) = Some(E)
    pub fn append(&self, bytes: &[u8]) -> Result<usize, WriteError> {
        let idx = self.len();

        debug_assert!(idx <= u32::MAX as usize);

        let n = idx as u32;

        if n == self.max_entries {
            return Err(WriteError::IndexFull { max_entries: n });
        }

        let offset = if n == 0 {
            0
        } else {
            read_u64(&self.memory, self.index_entry_offset(n - 1))
        };

        let new_offset = offset
            .checked_add(bytes.len() as u64)
            .expect("address overflow");

        let entry_offset = self
            .entries_offset
            .checked_add(offset)
            .expect("address overflow");

        debug_assert!(new_offset >= offset);

        // NB. we attempt to write the data first:
        //   1. We won't need to undo changes to the index if the write fails.
        //   2. A successful write will automatically allocate space for index updates
        //      because the data lives at higher addresses than the index.
        safe_write(&self.memory, entry_offset, bytes)?;

        write_u32(&self.memory, Address::from(self.index_offset), n + 1);
        write_u64(&self.memory, self.index_entry_offset(n), new_offset);

        debug_assert_eq!(self.get(idx), Some(bytes.to_vec()));

        Ok(idx)
    }

    /// Returns the offset and the length of the specified entry.
    fn entry_meta(&self, idx: usize) -> Option<(u64, usize)> {
        if self.len() <= idx {
            return None;
        }

        debug_assert!(idx <= u32::MAX as usize);

        let idx = idx as u32;

        if idx == 0 {
            Some((
                0,
                read_u64(&self.memory, self.index_entry_offset(0)) as usize,
            ))
        } else {
            let offset = read_u64(&self.memory, self.index_entry_offset(idx - 1));
            let next = read_u64(&self.memory, self.index_entry_offset(idx));

            debug_assert!(offset <= next);

            Some((offset, (next - offset) as usize))
        }
    }

    /// Returns the absolute offset of the specified index entry in memory.
    fn index_entry_offset(&self, idx: u32) -> Address {
        Address::from(
            self.index_offset
                + (idx as u64) * (std::mem::size_of::<u64>() as u64)
                + std::mem::size_of::<u32>() as u64,
        )
    }
}
