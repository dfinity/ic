use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::{CanisterId, PrincipalId};

#[async_trait]
pub trait Runtime {
    /// Returns the principal of the current canister.
    fn id() -> CanisterId;

    /// Prints a debug message.
    fn print(msg: impl AsRef<str>);

    /// Returns the current time in nanoseconds since the Unix epoch.
    fn time() -> u64;

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
        CanisterId::unchecked_from_principal(PrincipalId::from(ic_cdk::api::canister_self()))
    }

    fn print(msg: impl AsRef<str>) {
        ic_cdk::api::debug_print(msg)
    }

    fn time() -> u64 {
        ic_cdk::api::time()
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
        // We use `-1` as a sentinel for failures that do not have an associated
        // IC reject code (insufficient cycles, `ic0.call_perform` failure,
        // candid decoding errors). The positive range matches
        // `ic_error_types::RejectCode` so callers can reliably distinguish the
        // two. This mirrors the convention in
        // `rs/nervous_system/clients/src/exchange_rate_canister_client.rs`.
        const SENTINEL_CALL_FAILURE: i32 = -1;
        let response = ic_cdk::call::Call::unbounded_wait(principal_id.into(), method)
            .with_args(&args)
            .with_cycles(cycles as u128)
            .await
            .map_err(|err| match err {
                ic_cdk::call::CallFailed::CallRejected(rejected) => (
                    rejected
                        .reject_code()
                        .map(|code| code as i32)
                        .unwrap_or(SENTINEL_CALL_FAILURE),
                    rejected.reject_message().to_string(),
                ),
                ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(e) => {
                    (SENTINEL_CALL_FAILURE, e.to_string())
                }
                ic_cdk::call::CallFailed::CallPerformFailed(e) => {
                    (SENTINEL_CALL_FAILURE, e.to_string())
                }
            })?;
        response
            .candid_tuple::<Out>()
            .map_err(|err| (SENTINEL_CALL_FAILURE, err.to_string()))
    }
}
