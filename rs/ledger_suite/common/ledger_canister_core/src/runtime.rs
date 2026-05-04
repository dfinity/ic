#![allow(deprecated)]
use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::{CanisterId, PrincipalId};

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

/// Returns the amount of heap memory in bytes that has been allocated.
#[cfg(target_arch = "wasm32")]
pub fn heap_memory_size_bytes() -> usize {
    const WASM_PAGE_SIZE_BYTES: usize = 65536;
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn heap_memory_size_bytes() -> usize {
    0
}

#[derive(Debug)]
pub struct CdkRuntime;

#[async_trait]
impl Runtime for CdkRuntime {
    fn id() -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(ic_cdk::api::id()))
    }

    fn print(msg: impl AsRef<str>) {
        ic_cdk::api::print(msg)
    }

    async fn call<In, Out>(
        id: CanisterId,
        method: &str,
        cycles: u64,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        let principal_id = PrincipalId::from(id);
        ic_cdk::api::call::call_with_payment(principal_id.into(), method, args, cycles)
            .await
            .map_err(|(code, msg)| (code as i32, msg))
    }
}
