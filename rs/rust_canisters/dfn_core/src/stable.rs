use std::convert::TryFrom;
use std::io;

use crate::api::ic0;

/// The wasm page size is 64KiB
const PAGE_SIZE: f64 = 64.0 * 1024.0;

/// We store all the data prepended by the length of data in the first 4 bytes
/// 0        4             4 + length
/// +--------+-----------------+-------->
/// | length |     content     |  junk
/// +--------+-----------------+-------->

const LENGTH_BYTES: u32 = 4;

pub fn stable64_size() -> u64 {
    unsafe { ic0::stable64_size() }
}

pub fn stable64_grow(additional_pages: u64) -> i64 {
    unsafe { ic0::stable64_grow(additional_pages) }
}

pub fn stable64_write(offset: u64, data: &[u8]) {
    unsafe {
        ic0::stable64_write(offset, data.as_ptr() as u64, data.len() as u64);
    }
}

pub fn stable64_read(buf: &mut [u8], offset: u64, size: u64) {
    unsafe {
        ic0::stable64_read(buf.as_mut_ptr() as u64, offset, size);
    }
}

/// Sets the contents of the stable memory
pub fn set(content: &[u8]) {
    let len: u32 = content.len() as u32;
    ensure_capacity(len);
    unsafe {
        ic0::stable_write(LENGTH_BYTES, content.as_ptr() as u32, len);
    }
    set_length(len);
}

/// Writes `content` to the given offset in the stable memory
pub fn write(content: &[u8], offset: u32) {
    let min_len = u32::try_from(content.len() + usize::try_from(offset).unwrap())
        .expect("stable::write: content size + offset is too large");

    let current_pages = unsafe { ic0::stable_size() };

    let old_len = if current_pages == 0 { 0 } else { length() };
    let new_len = std::cmp::max(old_len, min_len);

    if new_len > old_len {
        ensure_capacity(new_len);
    }

    // Don't call stable_write unless we have data to write. This also avoids an
    // error when offset=0 and content is empty: in this case we don't allocate
    // any pages so write fails.
    if content.is_empty() {
        return;
    }

    unsafe {
        ic0::stable_write(
            LENGTH_BYTES + offset,
            content.as_ptr() as u32,
            content.len() as u32,
        );
    }

    if new_len > old_len {
        set_length(new_len);
    }
}

/// Gets the contents of the stable memory
pub fn get() -> Vec<u8> {
    let len = length();
    let mut out: Vec<u8> = vec![0; len as usize];
    unsafe {
        ic0::stable_read(out.as_mut_ptr() as u32, LENGTH_BYTES, len as u32);
    }
    out
}

/// Reads `len` bytes from `offset` in stable memory
pub fn read(offset: u32, len: u32) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; len as usize];
    unsafe {
        ic0::stable_read(out.as_mut_ptr() as u32, LENGTH_BYTES + offset, len);
    }
    out
}

pub fn length() -> u32 {
    let mut len_bytes: [u8; 4] = [0; 4];
    unsafe {
        ic0::stable_read(len_bytes.as_mut_ptr() as u32, 0, LENGTH_BYTES);
    }
    u32::from_le_bytes(len_bytes)
}

pub fn set_length(len: u32) {
    ensure_capacity(LENGTH_BYTES);
    let len_bytes = len.to_le_bytes();
    unsafe { ic0::stable_write(0, len_bytes.as_ptr() as u32, LENGTH_BYTES) }
}

fn ensure_capacity(capacity_bytes: u32) {
    let required_pages = (f64::from(capacity_bytes + LENGTH_BYTES) / PAGE_SIZE).ceil() as u32;
    let current_pages = unsafe { ic0::stable_size() };

    if required_pages > current_pages {
        let difference = required_pages - current_pages;
        unsafe {
            ic0::stable_grow(difference);
        };
    }
}

/// A writer to the stable memory. Will attempt to grow the memory as it
/// writes, and keep offsets and total capacity.
pub struct StableWriter {
    /// The offset of the next write.
    offset: usize,
    /// The capacity, in pages.
    capacity: u32,
    /// The number of bytes written so far.
    bytes_written: usize,
}

impl Default for StableWriter {
    fn default() -> Self {
        let capacity = unsafe { ic0::stable_size() };

        Self {
            offset: 4,
            capacity,
            bytes_written: 0,
        }
    }
}

impl StableWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to grow the memory by adding new pages.
    pub fn grow(&mut self, added_pages: u32) -> Result<(), io::Error> {
        let old_page_count = unsafe { ic0::stable_grow(added_pages) };
        if old_page_count < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to grow stable memory",
            ));
        }
        self.capacity = old_page_count as u32 + added_pages;
        Ok(())
    }
}

impl io::Write for StableWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if self.offset.saturating_add(buf.len()) > ((self.capacity as usize) << 16) {
            self.grow(((buf.len().saturating_add(65535)) >> 16) as u32)?;
        }

        unsafe {
            ic0::stable_write(self.offset as u32, buf.as_ptr() as u32, buf.len() as u32);
        }

        self.offset += buf.len();
        self.bytes_written += buf.len();

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        if self.capacity > 0 {
            set_length(self.bytes_written as u32);
        }
        Ok(())
    }
}

impl Drop for StableWriter {
    fn drop(&mut self) {
        use std::io::Write;
        self.flush().expect("failed to flush stable memory")
    }
}

/// A reader to the stable memory. Keeps an offset and reads off stable memory
/// consecutively up the size stored in the first 4 bytes of the stable memory.
pub struct StableReader {
    /// The offset of the next read.
    offset: usize,
    bytes_left: usize,
}

impl StableReader {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for StableReader {
    fn default() -> Self {
        let num_pages = unsafe { ic0::stable_size() };
        if num_pages == 0 {
            return Self {
                offset: 0,
                bytes_left: 0,
            };
        }

        let bytes_left = length();
        Self {
            offset: 4,
            bytes_left: bytes_left as usize,
        }
    }
}

impl io::Read for StableReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let to_read = buf.len().min(self.bytes_left);
        unsafe {
            ic0::stable_read(buf.as_mut_ptr() as u32, self.offset as u32, to_read as u32);
        }
        self.offset += to_read;
        self.bytes_left -= to_read;
        Ok(to_read)
    }
}
