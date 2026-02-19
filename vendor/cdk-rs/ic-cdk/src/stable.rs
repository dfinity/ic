//! APIs to manage stable memory.
//!
//! You can check the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-stable-memory)
//! for a in-depth explanation of stable memory.
// mod canister;
// #[cfg(test)]
// mod tests;

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

/// A standard implementation of [`StableMemory`].
///
/// Useful for creating [`StableWriter`] and [`StableReader`].
#[derive(Default, Debug, Copy, Clone)]
pub struct CanisterStableMemory {}

impl StableMemory for CanisterStableMemory {
    fn stable_size(&self) -> u64 {
        ic0::stable64_size()
    }

    fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError> {
        match ic0::stable64_grow(new_pages) {
            u64::MAX => Err(StableMemoryError::OutOfMemory),
            x => Ok(x),
        }
    }

    fn stable_write(&self, offset: u64, buf: &[u8]) {
        ic0::stable64_write(buf, offset);
    }

    fn stable_read(&self, offset: u64, buf: &mut [u8]) {
        ic0::stable64_read(buf, offset);
    }
}

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
    // SAFETY: ic0::stable64_read writes to all of `vec[0..size]`, so `set_len` is safe to call with the new size.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct TestStableMemory {
        memory: Rc<Mutex<Vec<u8>>>,
    }

    impl TestStableMemory {
        pub fn new(memory: Rc<Mutex<Vec<u8>>>) -> TestStableMemory {
            let bytes_len = memory.lock().unwrap().len();
            if bytes_len > 0 {
                let pages_required = pages_required(bytes_len);
                let bytes_required = pages_required * WASM_PAGE_SIZE_IN_BYTES;
                memory
                    .lock()
                    .unwrap()
                    .resize(bytes_required.try_into().unwrap(), 0);
            }

            TestStableMemory { memory }
        }
    }

    impl StableMemory for TestStableMemory {
        fn stable_size(&self) -> u64 {
            let bytes_len = self.memory.lock().unwrap().len();
            pages_required(bytes_len)
        }

        fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError> {
            let new_bytes = new_pages * WASM_PAGE_SIZE_IN_BYTES;

            let mut vec = self.memory.lock().unwrap();
            let previous_len = vec.len() as u64;
            let new_len = vec.len() as u64 + new_bytes;
            vec.resize(new_len.try_into().unwrap(), 0);
            Ok(previous_len / WASM_PAGE_SIZE_IN_BYTES)
        }

        fn stable_write(&self, offset: u64, buf: &[u8]) {
            let offset = offset as usize;

            let mut vec = self.memory.lock().unwrap();
            if offset + buf.len() > vec.len() {
                panic!("stable memory out of bounds");
            }
            vec[offset..(offset + buf.len())].clone_from_slice(buf);
        }

        fn stable_read(&self, offset: u64, buf: &mut [u8]) {
            let offset = offset as usize;

            let vec = self.memory.lock().unwrap();
            let count_to_copy = buf.len();

            buf[..count_to_copy].copy_from_slice(&vec[offset..offset + count_to_copy]);
        }
    }

    fn pages_required(bytes_len: usize) -> u64 {
        let page_size = WASM_PAGE_SIZE_IN_BYTES;
        (bytes_len as u64).div_ceil(page_size)
    }

    mod stable_writer_tests {
        use super::*;
        use rstest::rstest;
        use std::io::{Seek, Write};

        #[rstest]
        #[case(None)]
        #[case(Some(1))]
        #[case(Some(10))]
        #[case(Some(100))]
        #[case(Some(1000))]
        fn write_single_slice(#[case] buffer_size: Option<usize>) {
            let memory = Rc::new(Mutex::new(Vec::new()));
            let mut writer = build_writer(TestStableMemory::new(memory.clone()), buffer_size);

            let bytes = vec![1; 100];

            writer.write_all(&bytes).unwrap();
            writer.flush().unwrap();

            let result = &*memory.lock().unwrap();

            assert_eq!(bytes, result[..bytes.len()]);
        }

        #[rstest]
        #[case(None)]
        #[case(Some(1))]
        #[case(Some(10))]
        #[case(Some(100))]
        #[case(Some(1000))]
        fn write_many_slices(#[case] buffer_size: Option<usize>) {
            let memory = Rc::new(Mutex::new(Vec::new()));
            let mut writer = build_writer(TestStableMemory::new(memory.clone()), buffer_size);

            for i in 1..100 {
                let bytes = vec![i as u8; i];
                writer.write_all(&bytes).unwrap();
            }
            writer.flush().unwrap();

            let result = &*memory.lock().unwrap();

            let mut offset = 0;
            for i in 1..100 {
                let bytes = &result[offset..offset + i];
                assert_eq!(bytes, vec![i as u8; i]);
                offset += i;
            }
        }

        #[rstest]
        #[case(None)]
        #[case(Some(1))]
        #[case(Some(10))]
        #[case(Some(100))]
        #[case(Some(1000))]
        fn ensure_only_requests_min_number_of_pages_required(#[case] buffer_size: Option<usize>) {
            let memory = Rc::new(Mutex::new(Vec::new()));
            let mut writer = build_writer(TestStableMemory::new(memory.clone()), buffer_size);

            let mut total_bytes = 0;
            for i in 1..10000 {
                let bytes = vec![i as u8; i];
                writer.write_all(&bytes).unwrap();
                total_bytes += i;
            }
            writer.flush().unwrap();

            let capacity_pages = TestStableMemory::new(memory).stable_size();
            let min_pages_required = (total_bytes as u64).div_ceil(WASM_PAGE_SIZE_IN_BYTES);

            assert_eq!(capacity_pages, min_pages_required);
        }

        #[test]
        fn check_offset() {
            const WRITE_SIZE: usize = 1025;

            let memory = Rc::new(Mutex::new(Vec::new()));
            let mut writer = StableWriter::with_memory(TestStableMemory::new(memory.clone()), 0);
            assert_eq!(writer.offset(), 0);
            assert_eq!(writer.write(&vec![0; WRITE_SIZE]).unwrap(), WRITE_SIZE);
            assert_eq!(writer.offset(), WRITE_SIZE as u64);

            let mut writer = BufferedStableWriter::with_writer(
                WRITE_SIZE - 1,
                StableWriter::with_memory(TestStableMemory::new(memory), 0),
            );
            assert_eq!(writer.offset(), 0);
            assert_eq!(writer.write(&vec![0; WRITE_SIZE]).unwrap(), WRITE_SIZE);
            assert_eq!(writer.offset(), WRITE_SIZE as u64);
        }

        #[test]
        fn test_seek() {
            let memory = Rc::new(Mutex::new(Vec::new()));
            let mut writer = StableWriter::with_memory(TestStableMemory::new(memory.clone()), 0);
            writer
                .seek(std::io::SeekFrom::Start(WASM_PAGE_SIZE_IN_BYTES))
                .unwrap();
            assert_eq!(writer.stream_position().unwrap(), WASM_PAGE_SIZE_IN_BYTES);
            assert_eq!(writer.write(&[1_u8]).unwrap(), 1);
            assert_eq!(
                writer.seek(std::io::SeekFrom::End(0)).unwrap(),
                WASM_PAGE_SIZE_IN_BYTES * 2
            );
            let capacity_pages = TestStableMemory::new(memory).stable_size();
            assert_eq!(capacity_pages, 2);
        }

        fn build_writer(memory: TestStableMemory, buffer_size: Option<usize>) -> Box<dyn Write> {
            let writer = StableWriter::with_memory(memory, 0);
            if let Some(buffer_size) = buffer_size {
                Box::new(BufferedStableWriter::with_writer(buffer_size, writer))
            } else {
                Box::new(writer)
            }
        }
    }

    mod stable_reader_tests {
        use super::*;
        use rstest::rstest;
        use std::io::{Read, Seek};

        #[rstest]
        #[case(None)]
        #[case(Some(1))]
        #[case(Some(10))]
        #[case(Some(100))]
        #[case(Some(1000))]
        fn reads_all_bytes(#[case] buffer_size: Option<usize>) {
            let input = vec![1; 10_000];
            let memory = Rc::new(Mutex::new(input.clone()));
            let mut reader = build_reader(TestStableMemory::new(memory), buffer_size);

            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();

            assert_eq!(input, output[..input.len()]);
        }

        #[test]
        fn check_offset() {
            const READ_SIZE: usize = 1025;

            let memory = Rc::new(Mutex::new(vec![1; READ_SIZE]));
            let mut reader = StableReader::with_memory(TestStableMemory::new(memory.clone()), 0);
            assert_eq!(reader.offset(), 0);
            let mut bytes = vec![0; READ_SIZE];
            assert_eq!(reader.read(&mut bytes).unwrap(), READ_SIZE);
            assert_eq!(reader.offset(), READ_SIZE as u64);

            let mut reader = BufferedStableReader::with_reader(
                READ_SIZE - 1,
                StableReader::with_memory(TestStableMemory::new(memory), 0),
            );
            assert_eq!(reader.offset(), 0);
            let mut bytes = vec![0; READ_SIZE];
            assert_eq!(reader.read(&mut bytes).unwrap(), READ_SIZE);
            assert_eq!(reader.offset(), READ_SIZE as u64);
        }

        #[test]
        fn test_seek() {
            const SIZE: usize = 1025;
            let memory = Rc::new(Mutex::new((0..SIZE).map(|v| v as u8).collect::<Vec<u8>>()));
            let mut reader = StableReader::with_memory(TestStableMemory::new(memory), 0);
            let mut bytes = vec![0_u8; 1];

            const OFFSET: usize = 200;
            reader
                .seek(std::io::SeekFrom::Start(OFFSET as u64))
                .unwrap();
            assert_eq!(reader.stream_position().unwrap() as usize, OFFSET);
            assert_eq!(reader.read(&mut bytes).unwrap(), 1);
            assert_eq!(&bytes, &[OFFSET as u8]);
            assert_eq!(
                reader.seek(std::io::SeekFrom::End(0)).unwrap(),
                WASM_PAGE_SIZE_IN_BYTES
            );
            reader
                .seek(std::io::SeekFrom::Start(WASM_PAGE_SIZE_IN_BYTES * 2))
                .unwrap();
            // out of bounds so should fail
            assert!(reader.read(&mut bytes).is_err());
        }

        fn build_reader(memory: TestStableMemory, buffer_size: Option<usize>) -> Box<dyn Read> {
            let reader = StableReader::with_memory(memory, 0);
            if let Some(buffer_size) = buffer_size {
                Box::new(BufferedStableReader::with_reader(buffer_size, reader))
            } else {
                Box::new(reader)
            }
        }
    }
}
