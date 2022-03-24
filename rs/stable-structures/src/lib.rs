mod btreemap;
mod types;
pub mod vec_mem;

const WASM_PAGE_SIZE: u64 = 65536;

pub trait Memory {
    /// Returns the current size of the stable memory in WebAssembly
    /// pages. (One WebAssembly page is 64Ki bytes.)
    fn size(&self) -> u64;

    /// Tries to grow the memory by new_pages many pages containing
    /// zeroes.  If successful, returns the previous size of the
    /// memory (in pages).  Otherwise, returns -1.
    fn grow(&self, pages: u64) -> i64;

    /// Copies the data referred to by offset out of the stable memory
    /// and replaces the corresponding bytes in dst.
    fn read(&self, offset: u64, dst: &mut [u8]);

    /// Copies the data referred to by src and replaces the
    /// corresponding segment starting at offset in the stable memory.
    fn write(&self, offset: u64, src: &[u8]);
}

/// A helper function that reads a single 32bit integer encoded as
/// little-endian from the specified memory at the specified offset.
fn _read_u32<M: Memory>(m: &M, offset: u64) -> u32 {
    let mut buf: [u8; 4] = [0; 4];
    m.read(offset, &mut buf);
    u32::from_le_bytes(buf)
}

/// RestrictedMemory creates a limited view of another memory.  This
/// allows one to divide the main memory into non-intersecting ranges
/// and use different layouts in each region.
pub struct RestrictedMemory<M: Memory> {
    page_range: core::ops::Range<u64>,
    memory: M,
}

impl<M: Memory> RestrictedMemory<M> {
    pub fn new(memory: M, page_range: core::ops::Range<u64>) -> Self {
        assert!(page_range.end < u64::MAX / WASM_PAGE_SIZE);
        Self { memory, page_range }
    }
}

impl<M: Memory> Memory for RestrictedMemory<M> {
    fn size(&self) -> u64 {
        let base_size = self.memory.size();
        if base_size < self.page_range.start {
            0
        } else if base_size > self.page_range.end {
            self.page_range.end - self.page_range.start
        } else {
            base_size - self.page_range.start
        }
    }

    fn grow(&self, delta: u64) -> i64 {
        let base_size = self.memory.size();
        if base_size < self.page_range.start {
            self.memory
                .grow(self.page_range.start - base_size + delta)
                .min(0)
        } else if base_size >= self.page_range.end {
            if delta == 0 {
                (self.page_range.end - self.page_range.start) as i64
            } else {
                -1
            }
        } else {
            let pages_left = self.page_range.end - base_size;
            if pages_left < delta {
                -1
            } else {
                let r = self.memory.grow(delta);
                if r < 0 {
                    r
                } else {
                    r - self.page_range.start as i64
                }
            }
        }
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        self.memory
            .read(self.page_range.start * WASM_PAGE_SIZE + offset, dst)
    }

    fn write(&self, offset: u64, src: &[u8]) {
        self.memory
            .write(self.page_range.start * WASM_PAGE_SIZE + offset, src)
    }
}
