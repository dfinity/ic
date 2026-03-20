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
        ic_cdk::call::Call::unbounded_wait(id, method)
            .with_args(&args)
            .await
            .map_err(|e| match e {
                ic_cdk::call::CallFailed::CallRejected(r) => {
                    (r.raw_reject_code() as i32, r.reject_message().to_string())
                }
                other => (0, other.to_string()),
            })
            .and_then(|response| {
                response
                    .candid_tuple::<Out>()
                    .map_err(|e| (0, e.to_string()))
            })
    }
}
