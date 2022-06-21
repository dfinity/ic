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
