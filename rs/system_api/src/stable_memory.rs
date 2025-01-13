use std::convert::TryInto;

use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult,
    TrapCode::{HeapOutOfBounds, StableMemoryOutOfBounds, StableMemoryTooBigFor32Bit},
};
use ic_replicated_state::{canister_state::WASM_PAGE_SIZE_IN_BYTES, page_map, NumWasmPages};
use ic_types::NumOsPages;

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: usize = 64 * 1024; // 4GiB

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
    pub stable_memory_size: NumWasmPages,
}

impl StableMemory {
    pub fn new(stable_memory: ic_replicated_state::Memory) -> Self {
        Self {
            stable_memory_buffer: page_map::Buffer::new(stable_memory.page_map),
            stable_memory_size: stable_memory.size,
        }
    }

    /// Returns the stable memory size in Wasm pages after checking that it fits
    /// into an unsigned 32-bit integer.
    pub(super) fn stable_size(&self) -> HypervisorResult<u32> {
        let size = self.stable_memory_size.get();
        if size > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryTooBigFor32Bit,
                backtrace: None,
            });
        }

        // Safe as we confirmed above the value is small enough to fit into 32-bits.
        Ok(size.try_into().unwrap())
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

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES) {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        if dst + size > heap.len() {
            return Err(HypervisorError::Trapped {
                trap_code: HeapOutOfBounds,
                backtrace: None,
            });
        }
        self.stable_memory_buffer
            .read(&mut heap[dst..dst + size], offset);
        Ok(())
    }

    /// Writes from heap to stable memory.
    /// Returns the number of **new** dirty pages created by the write.
    pub(super) fn stable_write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES) {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        if src + size > heap.len() {
            return Err(HypervisorError::Trapped {
                trap_code: HeapOutOfBounds,
                backtrace: None,
            });
        }

        self.stable_memory_buffer
            .write(&heap[src..src + size], offset);
        Ok(())
    }

    /// Same as `stable64_read`, but doesn't do any bounds checks on the stable
    /// memory. This should only be called through instrumented code that does
    /// its own bounds checking (although it is still safe to call without
    /// bounds checking - the result will just be that zeros are read from
    /// beyond the end of stable memory).
    pub(super) fn stable_read_without_bounds_checks(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let (heap_end, overflow) = dst.overflowing_add(size);
        if overflow || heap_end as usize > heap.len() {
            return Err(HypervisorError::Trapped {
                trap_code: HeapOutOfBounds,
                backtrace: None,
            });
        }
        self.stable_memory_buffer
            .read(&mut heap[dst as usize..heap_end as usize], offset as usize);
        Ok(())
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
            .stable_memory_size
            .get()
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        let (heap_end, overflow) = dst.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped {
                trap_code: HeapOutOfBounds,
                backtrace: None,
            });
        }
        self.stable_memory_buffer
            .read(&mut heap[dst..heap_end], offset);
        Ok(())
    }

    /// Writes from heap to stable memory.
    ///
    /// Supports bigger stable memory indexed by 64 bit pointers.
    /// Returns the number of **new** dirty pages created by the write.
    pub(super) fn stable64_write(
        &mut self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        let (stable_memory_size_in_bytes, overflow) = self
            .stable_memory_size
            .get()
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes {
            return Err(HypervisorError::Trapped {
                trap_code: StableMemoryOutOfBounds,
                backtrace: None,
            });
        }

        let (heap_end, overflow) = src.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped {
                trap_code: HeapOutOfBounds,
                backtrace: None,
            });
        }

        self.stable_memory_buffer
            .write(&heap[src..heap_end], offset);
        Ok(())
    }

    /// Calculates the number of new dirty pages that a given write would
    /// create.
    ///
    /// No guarantee is made that such a write would succeed though (e.g. it
    /// could exceed the current stable memory size).
    pub(super) fn dirty_pages_from_write(&self, offset: u64, size: u64) -> NumOsPages {
        self.stable_memory_buffer
            .dirty_pages_from_write(offset, size)
    }
}
