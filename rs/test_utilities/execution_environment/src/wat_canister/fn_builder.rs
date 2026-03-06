//! Provides the per-function builder (`WatFnCode`) for a WAT canister.

/// The memory index region used by the Wasm `_wait` loop to simulate CPU work.
pub(crate) const WAIT_SCRATCHPAD_START: i32 = 65_000;

/// The memory offset where user-injected strings begin allocating.
pub(crate) const MEMORY_OFFSET_START: i32 = 1_000;

/// We assert that the user allocations (`MEMORY_OFFSET_START`) start early,
/// and the `_wait` scratchpad is parked at the extreme end of the memory page.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MEMORY_OFFSET_START < WAIT_SCRATCHPAD_START);

#[derive(Clone)]
pub(crate) enum FnCall {
    StableGrow(i32),
    StableRead(i32, i32, i32),
    GlobalTimerSet(i64),
    DebugPrint(Vec<u8>),
    Trap(Vec<u8>),
    Wait(i64),
    Loop(u32, Vec<FnCall>),
}

/// Create a new WAT function code builder.
pub fn wat_fn() -> WatFnCode {
    WatFnCode::new()
}

/// WAT function code builder, allows to chain function calls.
#[derive(Clone, Default)]
pub struct WatFnCode {
    pub(crate) calls: Vec<FnCall>,
}

impl WatFnCode {
    /// Create the content of a WAT function.
    pub fn new() -> Self {
        Self { calls: vec![] }
    }

    /// Call the `ic0.stable_grow` function.
    pub fn stable_grow(mut self, additional_pages: i32) -> Self {
        self.calls.push(FnCall::StableGrow(additional_pages));
        self
    }

    /// Call the `ic0.stable_read` function.
    pub fn stable_read(mut self, dst: i32, offset: i32, size: i32) -> Self {
        self.calls.push(FnCall::StableRead(dst, offset, size));
        self
    }

    /// Call the `ic0.global_timer_set` function.
    ///
    /// The name `api_global_timer_set` is similar to universal canister one.
    pub fn api_global_timer_set(mut self, timestamp: i64) -> Self {
        self.calls.push(FnCall::GlobalTimerSet(timestamp));
        self
    }

    /// Call the `ic0.debug_print` function.
    pub fn debug_print(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::DebugPrint(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap_with_blob(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::Trap(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap(self) -> Self {
        self.trap_with_blob(&[])
    }

    /// Wait for a given number of instructions.
    ///
    /// **WARNING**: This instruction simulates CPU cycles by executing `memory.fill` operations.
    /// It reserves and will completely clobber the WebAssembly memory addresses
    /// from `65,000` to `65,100`.
    pub fn wait(mut self, instructions: i64) -> Self {
        self.calls.push(FnCall::Wait(instructions));
        self
    }

    /// Loop a block of operations `count` times.
    ///
    /// This uses native WebAssembly `(loop)` instructions internally, meaning
    /// `count` can be extremely high (e.g. `100_000`) without inflating
    /// the generated Wasm binary size.
    pub fn repeat(mut self, count: u32, block: WatFnCode) -> Self {
        self.calls.push(FnCall::Loop(count, block.calls));
        self
    }
}
