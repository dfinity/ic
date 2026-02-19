//! APIs to manage stable memory.
//!
//! You can check the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-stable-memory)
//! for a in-depth explanation of stable memory.
mod canister;

pub use canister::CanisterStableMemory;
use std::{error, fmt, io};

/// WASM page size in bytes.
pub const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64KB

static CANISTER_STABLE_MEMORY: CanisterStableMemory = CanisterStableMemory {};

/// A trait defining the stable memory API which each canister running on the IC can make use of
pub trait StableMemory {
    /// Gets current size of the stable memory (in WASM pages).
    fn stable_size(&self) -> u64;

    /// Attempts to grow the stable memory by `new_pages` (added pages).
    ///
    /// Returns an error if it wasn't possible. Otherwise, returns the previous
    /// size that was reserved.
    ///
    /// *Note*: Pages are 64KiB in WASM.
    fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError>;

    /// Writes data to the stable memory location specified by an offset.
    ///
    /// Warning - this will panic if `offset + buf.len()` exceeds the current size of stable memory.
    /// Use `stable_grow` to request more stable memory if needed.
    fn stable_write(&self, offset: u64, buf: &[u8]);

    /// Reads data from the stable memory location specified by an offset.
    fn stable_read(&self, offset: u64, buf: &mut [u8]);
}

/// A possible error value when dealing with stable memory.
#[derive(Debug)]
pub enum StableMemoryError {
    /// No more stable memory could be allocated.
    OutOfMemory,
    /// Attempted to read more stable memory than had been allocated.
    OutOfBounds,
}

impl fmt::Display for StableMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => f.write_str("Out of memory"),
            Self::OutOfBounds => f.write_str("Read exceeds allocated memory"),
        }
    }
}

impl error::Error for StableMemoryError {}

/// Gets current size of the stable memory (in WASM pages).
pub fn stable_size() -> u64 {
    CANISTER_STABLE_MEMORY.stable_size()
}

/// Attempts to grow the stable memory by `new_pages` (added pages).
///
/// Returns an error if it wasn't possible. Otherwise, returns the previous
/// size that was reserved.
///
/// *Note*: Pages are 64KiB in WASM.
pub fn stable_grow(new_pages: u64) -> Result<u64, StableMemoryError> {
    CANISTER_STABLE_MEMORY.stable_grow(new_pages)
}

/// Writes data to the stable memory location specified by an offset.
///
/// Warning - this will panic if `offset + buf.len()` exceeds the current size of stable memory.
/// Use `stable_grow` to request more stable memory if needed.
pub fn stable_write(offset: u64, buf: &[u8]) {
    CANISTER_STABLE_MEMORY.stable_write(offset, buf);
}

/// Reads data from the stable memory location specified by an offset.
pub fn stable_read(offset: u64, buf: &mut [u8]) {
    CANISTER_STABLE_MEMORY.stable_read(offset, buf);
}

/// Returns a copy of the stable memory.
///
/// This will map the whole memory (even if not all of it has been written to).
///
/// # Panics
///
/// When the bytes of the stable memory cannot fit into a `Vec` which constrained by the usize.
pub fn stable_bytes() -> Vec<u8> {
    let size = (stable_size() << 16)
        .try_into()
        .expect("overflow: stable memory too large to read in one go");
    let mut vec = Vec::with_capacity(size);
    ic0::stable64_read_uninit(&mut vec.spare_capacity_mut()[..size], 0);
    // SAFETY: ic0.stable_read writes to all of `vec[0..size]`, so `set_len` is safe to call with the new size.
    unsafe {
        vec.set_len(size);
    }
    vec
}

/// Performs generic IO (read, write, and seek) on stable memory.
///
/// Warning: When using write functionality, this will overwrite any existing
/// data in stable memory as it writes, so ensure you set the `offset` value
/// accordingly if you wish to preserve existing data.
///
/// Will attempt to grow the memory as it writes,
/// and keep offsets and total capacity.
#[derive(Debug)]
pub struct StableIO<M: StableMemory = CanisterStableMemory> {
    /// The offset of the next write.
    offset: u64,

    /// The capacity, in pages.
    capacity: u64,

    /// The stable memory to write data to.
    memory: M,
}

impl Default for StableIO {
    fn default() -> Self {
        Self::with_memory(CanisterStableMemory::default(), 0)
    }
}

impl<M: StableMemory> StableIO<M> {
    /// Creates a new `StableIO` which writes to the selected memory
    pub fn with_memory(memory: M, offset: u64) -> Self {
        let capacity = memory.stable_size();
        Self {
            offset,
            capacity,
            memory,
        }
    }

    /// Returns the offset of the writer
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Attempts to grow the memory by adding new pages.
    pub fn grow(&mut self, new_pages: u64) -> Result<(), StableMemoryError> {
        let old_page_count = self.memory.stable_grow(new_pages)?;
        self.capacity = old_page_count + new_pages;
        Ok(())
    }

    /// Writes a byte slice to the buffer.
    ///
    /// # Errors
    ///
    /// When it cannot grow the memory to accommodate the new data.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, StableMemoryError> {
        let required_capacity_bytes = self.offset + buf.len() as u64;
        let required_capacity_pages = required_capacity_bytes.div_ceil(WASM_PAGE_SIZE_IN_BYTES);
        let current_pages = self.capacity;
        let additional_pages_required = required_capacity_pages.saturating_sub(current_pages);

        if additional_pages_required > 0 {
            self.grow(additional_pages_required)?;
        }

        self.memory.stable_write(self.offset, buf);
        self.offset += buf.len() as u64;
        Ok(buf.len())
    }

    /// Reads data from the stable memory location specified by an offset.
    ///
    /// # Errors
    ///
    /// The stable memory size is cached on creation of the `StableReader`.
    /// Therefore, in following scenario, it will get an `OutOfBounds` error:
    /// 1. Create a `StableReader`
    /// 2. Write some data to the stable memory which causes it grow
    /// 3. call `read()` to read the newly written bytes
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, StableMemoryError> {
        let capacity_bytes = self.capacity * WASM_PAGE_SIZE_IN_BYTES;
        let read_buf = if buf.len() as u64 + self.offset > capacity_bytes {
            if self.offset < capacity_bytes {
                // When usize=u32:
                //   (capacity_bytes - self.offset) < buf.len() <= u32::MAX == usize::MAX.
                // So the cast below won't panic.
                &mut buf[..(capacity_bytes - self.offset).try_into().unwrap()]
            } else {
                return Err(StableMemoryError::OutOfBounds);
            }
        } else {
            buf
        };
        self.memory.stable_read(self.offset, read_buf);
        self.offset += read_buf.len() as u64;
        Ok(read_buf.len())
    }

    // Helper used to implement io::Seek
    fn seek(&mut self, offset: io::SeekFrom) -> io::Result<u64> {
        self.offset = match offset {
            io::SeekFrom::Start(offset) => offset,
            io::SeekFrom::End(offset) => {
                ((self.capacity * WASM_PAGE_SIZE_IN_BYTES) as i64 + offset) as u64
            }
            io::SeekFrom::Current(offset) => (self.offset as i64 + offset) as u64,
        };

        Ok(self.offset)
    }
}

impl<M: StableMemory> io::Write for StableIO<M> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.write(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        // Noop.
        Ok(())
    }
}

impl<M: StableMemory> io::Read for StableIO<M> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        Self::read(self, buf).or(Ok(0)) // Read defines EOF to be success
    }
}

impl<M: StableMemory> io::Seek for StableIO<M> {
    fn seek(&mut self, offset: io::SeekFrom) -> io::Result<u64> {
        self.seek(offset)
    }
}

// impl_stable_io!(u32);
// impl_stable_io!(u64);

/// A writer to the stable memory.
///
/// Warning: This will overwrite any existing data in stable memory as it writes, so ensure you set
/// the `offset` value accordingly if you wish to preserve existing data.
///
/// Will attempt to grow the memory as it writes,
/// and keep offsets and total capacity.
#[derive(Debug)]
pub struct StableWriter<M: StableMemory = CanisterStableMemory>(StableIO<M>);

#[allow(clippy::derivable_impls)]
impl Default for StableWriter {
    #[inline]
    fn default() -> Self {
        Self(StableIO::default())
    }
}

impl<M: StableMemory> StableWriter<M> {
    /// Creates a new `StableWriter` which writes to the selected memory
    #[inline]
    pub fn with_memory(memory: M, offset: u64) -> Self {
        Self(StableIO::<M>::with_memory(memory, offset))
    }

    /// Returns the offset of the writer
    #[inline]
    pub fn offset(&self) -> u64 {
        self.0.offset()
    }

    /// Attempts to grow the memory by adding new pages.
    #[inline]
    pub fn grow(&mut self, new_pages: u64) -> Result<(), StableMemoryError> {
        self.0.grow(new_pages)
    }

    /// Writes a byte slice to the buffer.
    ///
    /// The only condition where this will
    /// error out is if it cannot grow the memory.
    #[inline]
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, StableMemoryError> {
        self.0.write(buf)
    }
}

impl<M: StableMemory> io::Write for StableWriter<M> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        io::Write::write(&mut self.0, buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), io::Error> {
        io::Write::flush(&mut self.0)
    }
}

impl<M: StableMemory> io::Seek for StableWriter<M> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.0, pos)
    }
}

impl<M: StableMemory> From<StableIO<M>> for StableWriter<M> {
    fn from(io: StableIO<M>) -> Self {
        Self(io)
    }
}

/// A writer to the stable memory which first writes the bytes to an in memory buffer and flushes
/// the buffer to stable memory each time it becomes full.
///
/// Warning: This will overwrite any existing data in stable memory as it writes, so ensure you set
/// the `offset` value accordingly if you wish to preserve existing data.
///
/// Note: Each call to grow or write to stable memory is a relatively expensive operation, so pick a
/// buffer size large enough to avoid excessive calls to stable memory.
#[derive(Debug)]
pub struct BufferedStableWriter<M: StableMemory = CanisterStableMemory> {
    inner: io::BufWriter<StableWriter<M>>,
}

impl BufferedStableWriter {
    /// Creates a new `BufferedStableWriter`
    pub fn new(buffer_size: usize) -> BufferedStableWriter {
        BufferedStableWriter::with_writer(buffer_size, StableWriter::default())
    }
}

impl<M: StableMemory> BufferedStableWriter<M> {
    /// Creates a new `BufferedStableWriter` which writes to the selected memory
    pub fn with_writer(buffer_size: usize, writer: StableWriter<M>) -> BufferedStableWriter<M> {
        BufferedStableWriter {
            inner: io::BufWriter::with_capacity(buffer_size, writer),
        }
    }

    /// Returns the offset of the writer
    pub fn offset(&self) -> u64 {
        self.inner.get_ref().offset()
    }
}

impl<M: StableMemory> io::Write for BufferedStableWriter<M> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<M: StableMemory> io::Seek for BufferedStableWriter<M> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.inner, pos)
    }
}

// A reader to the stable memory.
///
/// Keeps an offset and reads off stable memory consecutively.
#[derive(Debug)]
pub struct StableReader<M: StableMemory = CanisterStableMemory>(StableIO<M>);

#[allow(clippy::derivable_impls)]
impl Default for StableReader {
    fn default() -> Self {
        Self(StableIO::default())
    }
}

impl<M: StableMemory> StableReader<M> {
    /// Creates a new `StableReader` which reads from the selected memory
    #[inline]
    pub fn with_memory(memory: M, offset: u64) -> Self {
        Self(StableIO::<M>::with_memory(memory, offset))
    }

    /// Returns the offset of the reader
    #[inline]
    pub fn offset(&self) -> u64 {
        self.0.offset()
    }

    /// Reads data from the stable memory location specified by an offset.
    ///
    /// Note:
    /// The stable memory size is cached on creation of the `StableReader`.
    /// Therefore, in following scenario, it will get an `OutOfBounds` error:
    /// 1. Create a `StableReader`
    /// 2. Write some data to the stable memory which causes it grow
    /// 3. call `read()` to read the newly written bytes
    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, StableMemoryError> {
        self.0.read(buf)
    }
}

impl<M: StableMemory> io::Read for StableReader<M> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        io::Read::read(&mut self.0, buf)
    }
}

impl<M: StableMemory> io::Seek for StableReader<M> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.0, pos)
    }
}

impl<M: StableMemory> From<StableIO<M>> for StableReader<M> {
    fn from(io: StableIO<M>) -> Self {
        Self(io)
    }
}

/// A reader to the stable memory which reads bytes a chunk at a time as each chunk is required.
#[derive(Debug)]
pub struct BufferedStableReader<M: StableMemory = CanisterStableMemory> {
    inner: io::BufReader<StableReader<M>>,
}

impl BufferedStableReader {
    /// Creates a new `BufferedStableReader`
    pub fn new(buffer_size: usize) -> BufferedStableReader {
        BufferedStableReader::with_reader(buffer_size, StableReader::default())
    }
}

impl<M: StableMemory> BufferedStableReader<M> {
    /// Creates a new `BufferedStableReader` which reads from the selected memory
    pub fn with_reader(buffer_size: usize, reader: StableReader<M>) -> BufferedStableReader<M> {
        BufferedStableReader {
            inner: io::BufReader::with_capacity(buffer_size, reader),
        }
    }

    /// Returns the offset of the reader
    pub fn offset(&self) -> u64 {
        self.inner.get_ref().offset()
    }
}

impl<M: StableMemory> io::Read for BufferedStableReader<M> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<M: StableMemory> io::Seek for BufferedStableReader<M> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.inner, pos)
    }
}
