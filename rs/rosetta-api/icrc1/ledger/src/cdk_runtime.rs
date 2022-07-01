use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::runtime::Runtime;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct CdkRuntime;

#[async_trait]
impl Runtime for CdkRuntime {
    fn id() -> CanisterId {
        CanisterId::try_from(PrincipalId::from(ic_cdk::api::id())).unwrap()
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
