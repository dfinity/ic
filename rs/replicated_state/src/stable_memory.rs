use crate::{NumWasmPages, PageMap};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::system_metadata::v1 as pb;
use ic_sys::PAGE_SIZE;
use std::{convert::TryFrom, sync::Arc};

const WASM_PAGE_SIZE_IN_BYTES: u32 = 64 * 1024;
const MAX_STABLE_MEMORY_IN_PAGES: u32 = 64 * 1024; // 4GiB

#[derive(Clone, Debug)]
pub enum StableMemoryError {
    /// Attempting to access stable memory beyond its allocated bounds.
    StableMemoryOutOfBounds,
    /// Attempting to access the heap beyond its allocated bounds.
    HeapOutOfBounds,
}

/// An implementation of [stable memory](https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-stable-memory)
///
/// Canisters have the ability to store and retrieve data from a secondary
/// memory. The purpose of this stable memory is to provide space to store data
/// beyond upgrades. The interface mirrors roughly the memory-related
/// instructions of WebAssembly, and tries to be forward compatible with
/// exposing this feature as an additional memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableMemory {
    // Stores the memory as a vector of bytes. The vector is stored behind an
    // `Arc` to enable cheap clones of the canister state between rounds. If a
    // canister execution actually modifies the content, then we take a copy of
    // the whole vector.
    memory: Arc<Vec<u8>>,
}

impl Default for StableMemory {
    fn default() -> Self {
        Self {
            memory: Arc::new(vec![]),
        }
    }
}

impl StableMemory {
    /// Creates a flat stable memory from a page map representation.
    pub fn from_page_map(page_map: &PageMap, size: NumWasmPages) -> Self {
        let mut memory = vec![0; (size.get() * WASM_PAGE_SIZE_IN_BYTES) as usize];
        let page_size = *PAGE_SIZE;
        for (i, bytes) in page_map.host_pages_iter() {
            let offset = i.get() as usize * page_size;
            memory[offset..offset + page_size].copy_from_slice(bytes);
        }
        Self {
            memory: Arc::new(memory),
        }
    }

    /// Returns the current size of the stable memory in WebAssembly pages.
    pub fn page_count(&self) -> u32 {
        self.memory.len() as u32 / WASM_PAGE_SIZE_IN_BYTES
    }

    /// Tries to grow the memory by `additional_pages` more pages.
    ///
    /// The new memory is initialized with zeros. If successful, returns the
    /// previous size of the memory (in pages). Otherwise, returns -1.
    pub fn grow(&mut self, additional_pages: u32) -> i32 {
        let initial_page_count = self.page_count();

        if additional_pages > MAX_STABLE_MEMORY_IN_PAGES - initial_page_count {
            return -1;
        }

        let additional_size_in_bytes = (additional_pages * WASM_PAGE_SIZE_IN_BYTES) as usize;

        // Allocate additional memory in the vector.
        let memory = Arc::make_mut(&mut self.memory);
        memory.resize(memory.len() + additional_size_in_bytes, 0);
        initial_page_count as i32
    }

    /// Copies the data referred to by `offset`/`size` out of the stable memory
    /// and replaces the corresponding bytes starting at dst in the canister
    /// memory.
    pub fn read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> Result<(), StableMemoryError> {
        let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

        let (upper_bound, overflow) = offset.overflowing_add(size);
        if overflow || upper_bound > self.memory.len() {
            return Err(StableMemoryError::StableMemoryOutOfBounds);
        }

        let (upper_bound, overflow) = dst.overflowing_add(size);
        if overflow || upper_bound > heap.len() {
            return Err(StableMemoryError::HeapOutOfBounds);
        }

        heap[dst..dst + size].copy_from_slice(&self.memory[offset..offset + size]);
        Ok(())
    }

    /// Copies the data referred to by `src`/`size` out of the canister and
    /// replaces the corresponding segment starting at offset in the stable
    /// memory.
    pub fn write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> Result<(), StableMemoryError> {
        let (offset, src, size) = (offset as usize, src as usize, size as usize);

        let (upper_bound, overflow) = offset.overflowing_add(size);
        if overflow || upper_bound > self.memory.len() {
            return Err(StableMemoryError::StableMemoryOutOfBounds);
        }

        let (upper_bound, overflow) = src.overflowing_add(size);
        if overflow || upper_bound > heap.len() {
            return Err(StableMemoryError::HeapOutOfBounds);
        }

        // make_mut() will, if needed (clone-on-write) invoke clone on the inner
        // value to ensure unique ownership. This means that if write() is
        // called repeatedly in the same round of computation, only the first
        // call will actually clone the memory.
        let memory = Arc::make_mut(&mut self.memory);
        memory[offset..offset + size].copy_from_slice(&heap[src..src + size]);
        Ok(())
    }

    /// Clears everything in stable memory, including page allocations.
    pub fn clear(&mut self) {
        let memory = Arc::make_mut(&mut self.memory);
        memory.clear();
    }

    pub fn as_bytes(&self) -> &[u8] {
        &(*self.memory)[..]
    }
}

impl From<&StableMemory> for pb::StableMemory {
    fn from(item: &StableMemory) -> Self {
        Self {
            memory: (*item.memory).clone(),
        }
    }
}

impl TryFrom<pb::StableMemory> for StableMemory {
    type Error = ProxyDecodeError;

    fn try_from(item: pb::StableMemory) -> Result<Self, Self::Error> {
        if item.memory.len() / WASM_PAGE_SIZE_IN_BYTES as usize
            > MAX_STABLE_MEMORY_IN_PAGES as usize
        {
            return Err(ProxyDecodeError::Other(format!(
                "StableMemory: Size in pages ({}) is greater than maximum size ({})",
                item.memory.len() / WASM_PAGE_SIZE_IN_BYTES as usize,
                MAX_STABLE_MEMORY_IN_PAGES
            )));
        }
        if item.memory.len() % WASM_PAGE_SIZE_IN_BYTES as usize != 0 {
            return Err(ProxyDecodeError::Other(format!(
                "StableMemory: Size ({}) is not a multiple of WASM page size ({})",
                item.memory.len(),
                WASM_PAGE_SIZE_IN_BYTES
            )));
        }

        Ok(Self {
            memory: Arc::new(item.memory),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn stable_mem_grow_overflow() {
        let mut sm = StableMemory::default();
        assert_eq!(0, sm.grow(1));
        assert_eq!(-1, sm.grow(u32::MAX));
    }
}
