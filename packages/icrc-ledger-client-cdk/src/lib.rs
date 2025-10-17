use async_trait::async_trait;
use candid::{
    Principal,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
pub use icrc_ledger_client::{ICRC1Client, Runtime};

/// ICRC1Client runtime that uses the ic-cdk.
pub struct CdkRuntime;

#[async_trait]
impl Runtime for CdkRuntime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        #[allow(deprecated)]
        ic_cdk::call(id, method, args)
            .await
            .map_err(|(code, msg)| (code as i32, msg))
    }
}
