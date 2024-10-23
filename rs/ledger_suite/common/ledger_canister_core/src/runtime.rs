use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::CanisterId;

#[async_trait]
pub trait Runtime {
    /// Returns the principal of the current canister.
    fn id() -> CanisterId;

    /// Prints a debug message.
    fn print(msg: impl AsRef<str>);

    /// Invokes a Candid `method` on another canister identified by `id`.
    async fn call<In, Out>(
        id: CanisterId,
        method: &str,
        cycles: u64,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>;
}

/// Returns the total amount of memory (heap, stable memory, etc) that has been allocated.
#[cfg(target_arch = "wasm32")]
pub fn total_memory_size_bytes() -> usize {
    const WASM_PAGE_SIZE_BYTES: usize = 65536;
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn total_memory_size_bytes() -> usize {
    0
}
