use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, TrapCode::HeapOutOfBounds,
};
use ic_replicated_state::page_map;

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
}

impl StableMemory {
    pub fn new(stable_memory: ic_replicated_state::Memory) -> Self {
        Self {
            stable_memory_buffer: page_map::Buffer::new(stable_memory.page_map),
        }
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
}
