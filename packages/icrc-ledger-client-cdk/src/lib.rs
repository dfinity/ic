use async_trait::async_trait;
use candid::{
    Principal,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use ic_cdk::call::{Call, Error, RejectCode};
pub use icrc_ledger_client::{ICRC1Client, Runtime};

/// Translates a failed call into the `(reject code, message)` pair that
/// [`Runtime`] reports to its callers.
fn map_call_error(err: Error) -> (i32, String) {
    match err {
        Error::CallRejected(rejected) => (
            rejected.raw_reject_code() as i32,
            rejected.reject_message().to_string(),
        ),
        // A response that cannot be decoded means the callee misbehaved.
        Error::CandidDecodeFailed(err) => (RejectCode::CanisterError as i32, err.to_string()),
        // The call never left this canister, so it may well succeed if retried.
        err => (RejectCode::SysTransient as i32, err.to_string()),
    }
}

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
        Call::unbounded_wait(id, method)
            .with_args(&args)
            .await
            .map_err(Error::from)
            .and_then(|response| response.candid_tuple().map_err(Error::from))
            .map_err(map_call_error)
    }
}
