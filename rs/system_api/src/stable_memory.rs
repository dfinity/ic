use std::convert::TryInto;

use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult,
    TrapCode::{HeapOutOfBounds, StableMemoryOutOfBounds, StableMemoryTooBigFor32Bit},
};
use ic_replicated_state::{canister_state::WASM_PAGE_SIZE_IN_BYTES, page_map, NumWasmPages64};
use ic_types::MAX_STABLE_MEMORY_IN_BYTES;

const MAX_64_BIT_STABLE_MEMORY_IN_PAGES: u64 = MAX_STABLE_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES;
const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: u64 = if 64 * 1024 < MAX_64_BIT_STABLE_MEMORY_IN_PAGES {
    64 * 1024 // 4GiB
} else {
    MAX_64_BIT_STABLE_MEMORY_IN_PAGES
};

/// Essentially the same as a `page_map::Memory`, but we use a `Buffer` instead
/// of a `PageMap`.
pub struct StableMemory {
    /// We could update the PageMap stored in the system state directly, but it
    /// will be not efficient if the canister issues many write requests to
    /// nearby memory locations, which is a common case (serializing Candid
    /// directly to stable memory, for example).  Using a long-lived buffer
    /// allows us to allocate a dirty page once and modify it in-place in
    /// subsequent calls.
    pub stable_memory_buffer: page_map::Buffer,
    /// The size of the canister's stable memory.
    pub stable_memory_size: NumWasmPages64,
}

impl StableMemory {
    pub fn new(stable_memory: ic_replicated_state::Memory<NumWasmPages64>) -> Self {
        Self {
            stable_memory_buffer: page_map::Buffer::new(stable_memory.page_map),
            stable_memory_size: stable_memory.size,
        }
    }

    /// Determines size of stable memory in Web assembly pages.
    pub(super) fn stable_size(&self) -> HypervisorResult<u32> {
        let size = self.stable_memory_size.get();
        if size > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
            return Err(HypervisorError::Trapped(StableMemoryTooBigFor32Bit));
        }

        // Safe as we confirmed above the value is small enough to fit into 32-bits.
        Ok(size.try_into().unwrap())
    }

    /// Grows stable memory by specified amount.
    pub(super) fn stable_grow(&mut self, additional_pages: u32) -> HypervisorResult<i32> {
        let initial_page_count = self.stable_size()? as u64;
        let additional_pages = additional_pages as u64;

        if additional_pages + initial_page_count > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
            return Ok(-1);
        }

        self.stable_memory_size = NumWasmPages64::from(initial_page_count + additional_pages);

        Ok(initial_page_count
            .try_into()
            .expect("could not fit initial page count in 32 bits, although 32-bit api is used"))
    }

    /// Reads from stable memory back to heap.
    pub(super) fn stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES as usize) {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        if dst + size > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }
        self.stable_memory_buffer
            .read(&mut heap[dst..dst + size], offset);
        Ok(())
    }

    /// Writes from heap to stable memory.
    pub(super) fn stable_write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES as usize) {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        if src + size > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        self.stable_memory_buffer
            .write(&heap[src..src + size], offset);
        Ok(())
    }

    /// Determines size of stable memory in Web assembly pages.
    pub(super) fn stable64_size(&self) -> HypervisorResult<u64> {
        Ok(self.stable_memory_size.get())
    }

    /// Grows stable memory by specified amount.
    pub(super) fn stable64_grow(&mut self, additional_pages: u64) -> HypervisorResult<i64> {
        let initial_page_count = self.stable64_size()?;

        let (page_count, overflow) = additional_pages.overflowing_add(initial_page_count);
        if overflow || page_count > MAX_64_BIT_STABLE_MEMORY_IN_PAGES {
            return Ok(-1);
        }

        self.stable_memory_size = NumWasmPages64::from(initial_page_count + additional_pages);

        Ok(initial_page_count as i64)
    }

    /// Reads from stable memory back to heap.
    ///
    /// Supports bigger stable memory indexed by 64 bit pointers.
    pub(super) fn stable64_read(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

        let (stable_memory_size_in_bytes, overflow) = self
            .stable64_size()?
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes as usize {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (heap_end, overflow) = dst.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }
        self.stable_memory_buffer
            .read(&mut heap[dst..heap_end], offset);
        Ok(())
    }

    /// Writes from heap to stable memory.
    ///
    /// Supports bigger stable memory indexed by 64 bit pointers.
    pub(super) fn stable64_write(
        &mut self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        let (stable_memory_size_in_bytes, overflow) = self
            .stable64_size()?
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes as usize {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (heap_end, overflow) = src.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        self.stable_memory_buffer
            .write(&heap[src..heap_end], offset);
        Ok(())
    }
}
