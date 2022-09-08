//! This module implements append-only list data structure, also known as log.
//! It supports arbitrary-sized entries and dynamic sizing to arbitrary number of entries (as long as the underlying memory offers enough space).
//! This requires two _independently growable_ Memory trait objects. For canister development it is recommended to use a [crate::memory_manager].
//!
//! # V1 layout
//!
//! This log uses two [crate::Memory] trait objects:
//! * index memory to store the memory addresses of each entry
//! * data memory to store the entries themselves
//!
//! ## Index memory
//!
//! ```text
//! ---------------------------------------- <- Address 0
//! Magic "GLI"             ↕ 3 bytes
//! ----------------------------------------
//! Layout version          ↕ 1 byte
//! ----------------------------------------
//! Reserved space          ↕ 28 bytes
//! ---------------------------------------- <- Address 32 (HEADER_OFFSET)
//! Number of entries = L   ↕ 8 bytes
//! ---------------------------------------- <- Address 40
//! E_0                     ↕ 8 bytes         
//! ----------------------------------------
//! E_0 + E_1               ↕ 8 bytes
//! ----------------------------------------
//! ...
//! ----------------------------------------
//! E_0 + ... + E_(L-1)     ↕ 8 bytes
//! ----------------------------------------
//! Unused index entries    ↕ 8×(N-L) bytes
//! ----------------------------------------
//! Unallocated space
//! ```
//!
//! ## Data memory
//!
//! ```text
//! ---------------------------------------- <- Address 0
//! Magic "GLD"             ↕ 3 bytes
//! ----------------------------------------
//! Layout version          ↕ 1 byte
//! ----------------------------------------
//! Reserved space          ↕ 28 bytes
//! ---------------------------------------- <- Address 32 (HEADER_OFFSET)
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
use crate::{read_u64, safe_write, write_u64, Address, GrowFailed, Memory};

#[cfg(test)]
mod tests;

/// The magic number: Growable Log Index.
pub const INDEX_MAGIC: &[u8; 3] = b"GLI";
/// The magic number: Growable Log Data.
pub const DATA_MAGIC: &[u8; 3] = b"GLD";

/// The current version of the layout.
const LAYOUT_VERSION: u8 = 1;

/// The size of the V1 layout header.
const HEADER_V1_SIZE: u64 = 4;

/// The number of header bytes reserved for future extensions.
const RESERVED_HEADER_SIZE: u64 = 28;

/// Header offset to write data to.
const HEADER_OFFSET: u64 = HEADER_V1_SIZE + RESERVED_HEADER_SIZE;

struct HeaderV1 {
    magic: [u8; 3],
    version: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitError {
    IncompatibleDataVersion {
        last_supported_version: u8,
        decoded_version: u8,
    },
    IncompatibleIndexVersion {
        last_supported_version: u8,
        decoded_version: u8,
    },
    InvalidIndex,
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

/// Append-only list of variable-size entries stored in stable memory.
pub struct Log<INDEX: Memory, DATA: Memory> {
    index_memory: INDEX,
    data_memory: DATA,
}

impl<INDEX: Memory, DATA: Memory> Log<INDEX, DATA> {
    /// Creates a new empty growable stable log backed by the memory trait objects, overwriting the previous contents.
    pub fn new(index_memory: INDEX, data_memory: DATA) -> Self {
        let log = Self {
            index_memory,
            data_memory,
        };
        Self::write_header(
            &log.index_memory,
            &HeaderV1 {
                magic: *INDEX_MAGIC,
                version: LAYOUT_VERSION,
            },
        );
        Self::write_header(
            &log.data_memory,
            &HeaderV1 {
                magic: *DATA_MAGIC,
                version: LAYOUT_VERSION,
            },
        );

        // number of entries
        write_u64(&log.index_memory, Address::from(HEADER_OFFSET), 0);
        log
    }

    /// Initializes the log based on the contents of the provided memory trait objects.
    /// If the memory trait objects already contain a stable log, this function recovers it from the stable
    /// memory. Otherwise, this function allocates a new empty log.
    pub fn init(index_memory: INDEX, data_memory: DATA) -> Result<Self, InitError> {
        // if the data memory is not containing expected data, the index is useless anyway.
        if data_memory.size() == 0 {
            return Ok(Self::new(index_memory, data_memory));
        }
        let data_header = Self::read_header(&data_memory);
        if &data_header.magic != DATA_MAGIC {
            return Ok(Self::new(index_memory, data_memory));
        }

        if data_header.version != LAYOUT_VERSION {
            return Err(InitError::IncompatibleDataVersion {
                last_supported_version: LAYOUT_VERSION,
                decoded_version: data_header.version,
            });
        }

        let index_header = Self::read_header(&index_memory);
        if &index_header.magic != INDEX_MAGIC {
            return Err(InitError::InvalidIndex);
        }

        if index_header.version != LAYOUT_VERSION {
            return Err(InitError::IncompatibleIndexVersion {
                last_supported_version: LAYOUT_VERSION,
                decoded_version: index_header.version,
            });
        }

        #[cfg(debug_assertions)]
        {
            assert_eq!(Ok(()), Self::validate_v1_index(&index_memory));
        }

        Ok(Self {
            index_memory,
            data_memory,
        })
    }

    /// Writes the stable log header to memory.
    fn write_header(memory: &impl Memory, header: &HeaderV1) {
        if memory.size() < 1 {
            assert!(
                memory.grow(1) != -1,
                "failed to allocate the first memory page"
            );
        }
        memory.write(0, &header.magic);
        memory.write(3, &[header.version]);
    }

    /// Reads the stable log header from the memory.
    /// PRECONDITION: memory.size() > 0
    fn read_header(memory: &impl Memory) -> HeaderV1 {
        let mut magic = [0u8; 3];
        let mut version = [0u8; 1];
        memory.read(0, &mut magic);
        memory.read(3, &mut version);
        HeaderV1 {
            magic,
            version: version[0],
        }
    }

    #[cfg(debug_assertions)]
    fn validate_v1_index(memory: &INDEX) -> Result<(), String> {
        let num_entries = read_u64(memory, Address::from(HEADER_OFFSET));

        if num_entries == 0 {
            return Ok(());
        }

        // Check that the index entries are non-decreasing.
        let mut prev_entry = read_u64(memory, Address::from(HEADER_OFFSET + 8));
        for i in 1..(num_entries as u64) {
            let entry = read_u64(memory, Address::from(HEADER_OFFSET + 8 + i * 8));
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

    /// Returns the underlying memory trait objects of the log.
    pub fn forget(self) -> (INDEX, DATA) {
        (self.index_memory, self.data_memory)
    }

    /// Returns true iff this log does not have any entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of index memory bytes in use.
    pub fn index_size_bytes(&self) -> usize {
        let num_entries = read_u64(&self.index_memory, Address::from(HEADER_OFFSET));
        self.index_entry_offset(num_entries).get() as usize
    }

    /// Returns the number of data memory bytes in use.
    pub fn data_size_bytes(&self) -> usize {
        self.log_size_bytes() + HEADER_OFFSET as usize
    }

    /// Returns the total size of all logged entries in bytes.
    pub fn log_size_bytes(&self) -> usize {
        let num_entries = self.len();
        if num_entries == 0 {
            0
        } else {
            read_u64(
                &self.index_memory,
                self.index_entry_offset((num_entries - 1) as u64),
            ) as usize
        }
    }

    /// Returns the number of entries in the log.
    pub fn len(&self) -> usize {
        read_u64(&self.index_memory, Address::from(HEADER_OFFSET)) as usize
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
        self.data_memory.read((HEADER_OFFSET + offset) as u64, buf);
        Ok(())
    }

    /// Appends a new entry to the log.
    /// If successful, returns the index of the entry.
    ///
    /// POST-CONDITION: Ok(idx) = log.append(E) ⇒ log.get(idx) = Some(E)
    pub fn append(&self, bytes: &[u8]) -> Result<usize, WriteError> {
        let idx = self.len() as u64;
        let data_offset = if idx == 0 {
            0
        } else {
            read_u64(&self.index_memory, self.index_entry_offset(idx - 1))
        };

        let new_offset = data_offset
            .checked_add(bytes.len() as u64)
            .expect("address overflow");

        let entry_offset = HEADER_OFFSET
            .checked_add(data_offset)
            .expect("address overflow");

        debug_assert!(new_offset >= data_offset);

        // NB. we attempt to write the data first so we won't need to undo changes to the index if the write fails.
        safe_write(&self.data_memory, entry_offset, bytes)?;

        // NB. append to index first as it might need to grow the index memory.
        safe_write(
            &self.index_memory,
            self.index_entry_offset(idx).get(),
            &new_offset.to_le_bytes(),
        )?;
        // update number of entries
        write_u64(
            &self.index_memory,
            Address::from(HEADER_OFFSET),
            idx as u64 + 1,
        );

        debug_assert_eq!(self.get(idx as usize), Some(bytes.to_vec()));

        Ok(idx as usize)
    }

    /// Returns the offset and the length of the specified entry.
    fn entry_meta(&self, idx: usize) -> Option<(u64, usize)> {
        if self.len() <= idx {
            return None;
        }

        let idx = idx as u64;
        if idx == 0 {
            Some((
                0,
                read_u64(&self.index_memory, self.index_entry_offset(0)) as usize,
            ))
        } else {
            let offset = read_u64(&self.index_memory, self.index_entry_offset(idx - 1));
            let next = read_u64(&self.index_memory, self.index_entry_offset(idx));

            debug_assert!(offset <= next);

            Some((offset, (next - offset) as usize))
        }
    }

    /// Returns the absolute offset of the specified index entry in memory.
    fn index_entry_offset(&self, idx: u64) -> Address {
        Address::from(
            HEADER_OFFSET + std::mem::size_of::<u64>() as u64 // skip over u64 storing the number of entries
                + idx * (std::mem::size_of::<u64>() as u64), // memory addresses for idx many entries
        )
    }
}
