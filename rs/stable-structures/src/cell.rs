use crate::storable::Storable;
use crate::{Memory, WASM_PAGE_SIZE};
use std::borrow::Borrow;

#[cfg(test)]
mod tests;

const MAGIC: &[u8; 3] = b"SCL"; // short for "stable cell"
const HEADER_V1_SIZE: u64 = 8;
const LAYOUT_VERSION: u8 = 1;

// NOTE: the size of this structure should be equal to [HEADER_V1_SIZE].
// NOTE: if you have to add more fields, you need to increase the version and handle decoding of
// previous versions in `Cell::read_header`.
//
// # V1 layout
//
// -------------------------------
// Magic "SCL"         ↕ 3 bytes
// -------------------------------
// Layout version      ↕ 1 byte
// -------------------------------
// Value length = N    ↕ 4 bytes
// -------------------------------
// <encoded value>     ↕ N bytes
// -------------------------------
#[derive(Debug)]
struct HeaderV1 {
    magic: [u8; 3],
    version: u8,
    value_length: u32,
}

/// Indicates a failure to initialize a Cell.
#[derive(Debug, PartialEq)]
pub enum InitError {
    /// The version of the library does not support version of the cell layout encoded in the
    /// memory.
    IncompatibleVersion {
        last_supported_version: u8,
        decoded_version: u8,
    },
    /// The initial value was to large to fit into the memory.
    ValueTooLarge { value_size: u64 },
}

/// Indicates a failure to set cell's value.
#[derive(Debug, PartialEq)]
pub enum ValueError {
    /// The value is too large to fit into the cell memory.
    ValueTooLarge { value_size: u64 },
}

impl From<ValueError> for InitError {
    fn from(e: ValueError) -> InitError {
        match e {
            ValueError::ValueTooLarge { value_size } => InitError::ValueTooLarge { value_size },
        }
    }
}

/// Represents a serializable value stored in the stable memory.
/// It has semantics similar to "stable variables" in Motoko and share the same limitations.
/// The main difference is that Cell writes its value to the memory on each assignment, not just in
/// upgrade hooks.
/// You should use cells only for small (up to a few MiB) values to keep upgrades safe.
///
/// Cell is a good choice for small read-only configuration values set once on canister installation
/// and rarely updated.
pub struct Cell<T: Storable, M: Memory> {
    memory: M,
    value: T,
}

impl<T: Storable, M: Memory> Cell<T, M> {
    /// Creates a new cell in the specified memory, overwriting the previous contents of the memory.
    pub fn new(memory: M, value: T) -> Result<Self, ValueError> {
        Self::flush_value(&memory, &value)?;
        Ok(Self { memory, value })
    }

    /// Initializes the value of the cell based on the contents of the `memory`.
    /// If the memory already contains a cell, initializes the cell with the decoded value.
    /// Otherwise, sets the cell value to `default_value` and writes it to the memory.
    pub fn init(memory: M, default_value: T) -> Result<Self, InitError> {
        if memory.size() == 0 {
            return Ok(Self::new(memory, default_value)?);
        }

        let header = Self::read_header(&memory);

        if &header.magic != MAGIC {
            return Ok(Self::new(memory, default_value)?);
        }

        if header.version != LAYOUT_VERSION {
            return Err(InitError::IncompatibleVersion {
                last_supported_version: LAYOUT_VERSION,
                decoded_version: header.version,
            });
        }

        Ok(Self {
            value: Self::read_value(&memory, header.value_length),
            memory,
        })
    }

    /// Reads and decodes the value of specified length.
    ///
    /// PRECONDITION: memory is large enough to contain the value.
    fn read_value(memory: &M, len: u32) -> T {
        let mut buf = vec![0; len as usize];
        memory.read(HEADER_V1_SIZE, &mut buf);
        T::from_bytes(buf)
    }

    /// Reads the header from the specified memory.
    ///
    /// PRECONDITION: memory.size() > 0
    fn read_header(memory: &M) -> HeaderV1 {
        let mut magic: [u8; 3] = [0; 3];
        let mut version: [u8; 1] = [0; 1];
        let mut len: [u8; 4] = [0; 4];

        memory.read(0, &mut magic);
        memory.read(3, &mut version);
        memory.read(4, &mut len);

        HeaderV1 {
            magic,
            version: version[0],
            value_length: u32::from_le_bytes(len),
        }
    }

    /// Returns the current value in the cell.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Forgets the value in this cell and returns the underlying memory.
    pub fn forget(self) -> M {
        self.memory
    }

    /// Updates the current value in the cell.
    /// If the new value is too large to fit into the memory, the value in the cell does not
    /// change.
    pub fn set(&mut self, value: T) -> Result<T, ValueError> {
        Self::flush_value(&self.memory, &value)?;
        Ok(std::mem::replace(&mut self.value, value))
    }

    /// Writes the value to the memory, growing the memory size if needed.
    fn flush_value(memory: &M, value: &T) -> Result<(), ValueError> {
        let encoded = value.to_bytes();
        let bytes: &[u8] = encoded.borrow();
        let len = bytes.len();
        if len > u32::MAX as usize {
            return Err(ValueError::ValueTooLarge {
                value_size: len as u64,
            });
        }
        let size = memory.size();
        let available_space = size * WASM_PAGE_SIZE;
        if len as u64 > available_space.saturating_sub(HEADER_V1_SIZE) {
            let grow_by =
                (len as u64 + HEADER_V1_SIZE + WASM_PAGE_SIZE - size * WASM_PAGE_SIZE - 1)
                    / WASM_PAGE_SIZE;
            if memory.grow(grow_by) < 0 {
                return Err(ValueError::ValueTooLarge {
                    value_size: len as u64,
                });
            }
        }

        debug_assert!(memory.size() * WASM_PAGE_SIZE >= len as u64 + HEADER_V1_SIZE);

        let version = [LAYOUT_VERSION; 1];
        memory.write(0, MAGIC);
        memory.write(3, &version);
        memory.write(4, &(len as u32).to_le_bytes());
        memory.write(HEADER_V1_SIZE, bytes);
        Ok(())
    }
}
