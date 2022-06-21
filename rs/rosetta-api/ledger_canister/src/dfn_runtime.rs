use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use dfn_core::api::Funds;
use ic_base_types::CanisterId;
use ic_ledger_core::runtime::Runtime;

#[derive(Debug)]
pub struct DfnRuntime;

#[async_trait]
impl Runtime for DfnRuntime {
    fn id() -> CanisterId {
        dfn_core::api::id()
    }

    fn print(msg: impl AsRef<str>) {
        dfn_core::api::print(msg)
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
        dfn_core::api::call_with_funds_and_cleanup(
            id,
            method,
            dfn_candid::candid_multi_arity,
            args,
            Funds::new(cycles),
        )
        .await
        .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }
}
