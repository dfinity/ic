use async_trait::async_trait;
use candid::{
    Principal,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use ic_cdk::call::{Call, Error, RejectCode};
pub use icrc_ledger_client::{ICRC1Client, Runtime};

/// Translates a failed call into the `(reject code, message)` pair that
/// [`Runtime`] reports to its callers.
///
/// The match is deliberately exhaustive (rather than using a catch-all arm) so
/// that a new [`Error`] variant forces us to revisit this mapping instead of
/// silently misclassifying it.
fn map_call_error(err: Error) -> (i32, String) {
    match err {
        // The system (or the callee) already rejected the call and assigned a reject
        // code; surface it unchanged.
        Error::CallRejected(rejected) => (
            rejected.raw_reject_code() as i32,
            rejected.reject_message().to_string(),
        ),
        // The callee replied, but its response did not decode into the expected type,
        // so it did not honor its interface: treat it as a canister-side error.
        Error::CandidDecodeFailed(err) => (RejectCode::CanisterError as i32, err.to_string()),
        // The call was not performed because this canister's liquid cycles balance
        // was too low. The protocol itself classifies an insufficient cycles balance
        // as `SysTransient`, so mirror that here rather than remapping it.
        Error::InsufficientLiquidCycleBalance(err) => {
            (RejectCode::SysTransient as i32, err.to_string())
        }
        // `ic0.call_perform` could not enqueue the call (e.g. a full output queue),
        // a transient system condition that a later retry may clear.
        Error::CallPerformFailed(err) => (RejectCode::SysTransient as i32, err.to_string()),
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
