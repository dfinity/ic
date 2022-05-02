use ic_replicated_state::page_map::{Buffer, PageMap, PersistenceError};
use stable_structures::Memory;
use std::sync::{Arc, Mutex};

const WASM_PAGE_SIZE_IN_BYTES: u64 = 65536;
const ONE_TB_IN_BYTES: u64 = 1 << 40;
const ONE_TB_IN_PAGES: u64 = ONE_TB_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES;

/// A memory backed by a [`PageMap`].
#[derive(Clone)]
pub struct PageMapMemory {
    buffer: Arc<Mutex<Buffer>>,
}

impl Default for PageMapMemory {
    fn default() -> Self {
        Self::new(PageMap::default())
    }
}

impl PageMapMemory {
    /// Initializes a new pagemap memory.
    pub fn new(page_map: PageMap) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Buffer::new(page_map))),
        }
    }

    /// Opens a memory from a file.
    pub fn open(path: &std::path::Path) -> Result<Self, PersistenceError> {
        let page_map = PageMap::open(path, None)?;
        Ok(Self::new(page_map))
    }

    /// Persists the memory to disk at the given path.
    pub fn persist_and_sync_delta(&self, path: &std::path::Path) -> Result<(), PersistenceError> {
        let page_delta: PageMap = self.buffer.lock().unwrap().into_page_map();
        page_delta.persist_and_sync_delta(path)?;
        let new_page_map = PageMap::open(path, None)?;
        *self.buffer.lock().unwrap() = Buffer::new(new_page_map);
        Ok(())
    }

    pub fn into_page_map(self) -> PageMap {
        self.buffer.lock().unwrap().into_page_map()
    }
}

impl Memory for PageMapMemory {
    fn size(&self) -> u64 {
        // A `PageMap` can in theory keep growing without bound.
        // Nevertheless, we cap the size at 1TiB.
        ONE_TB_IN_PAGES
    }

    fn grow(&self, _pages: u64) -> i64 {
        // Don't grow the pagemap beyond the above bound.
        -1
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        self.buffer.lock().unwrap().read(dst, offset as usize);
    }

    fn write(&self, offset: u64, src: &[u8]) {
        self.buffer.lock().unwrap().write(src, offset as usize);
    }
}
