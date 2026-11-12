use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::call::{Call, Error as IcCdkCallError, RejectCode};
use std::future::Future;

// A trait to help parameterize the switch from dfn_core to ic_cdk. It should
// no longer exist after the switch is completed for all NNS/SNS canisters.
#[async_trait]
pub trait Runtime: Send + Sync {
    // Invokes a Candid `method` on another canister identified by `id`.
    // Whether cleanup is done (call drop() on local variables in the context
    // upon a trap in its callback) depends on the specific Runtime
    // implementation.
    async fn call_without_cleanup<In, Out>(
        id: CanisterId,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>;

    // Invokes a Candid `method` on another canister identified by `id`.
    // The implementation must clean up its local variables despite a trap in
    // its callback.
    async fn call_with_cleanup<In, Out>(
        id: CanisterId,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>;

    // Invokes a Candid `method` on another canister identified by `id`, while
    // passing raw bytes as input/output.
    // The implementation must clean up its local variables despite a trap in
    // its callback.
    async fn call_bytes_with_cleanup(
        id: CanisterId,
        method: &str,
        args: &[u8],
    ) -> Result<Vec<u8>, (i32, String)>;

    // Spawns a future.
    fn spawn_future<F: 'static + Future<Output = ()>>(future: F);

    /// Get the canister version
    fn canister_version() -> u64;
}

pub struct DfnRuntime;

#[async_trait]
impl Runtime for DfnRuntime {
    // This method does not do clean up.
    async fn call_without_cleanup<In, Out>(
        id: CanisterId,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        // dfn_core::api::call always returns `Some(code)` when it fails so unwrap_or_default is fine.
        dfn_core::api::call(id, method, dfn_candid::candid_multi_arity, args)
            .await
            .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }

    async fn call_with_cleanup<In, Out>(
        id: CanisterId,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        // dfn_core::api::call_with_cleanup always returns `Some(code)` when it fails so unwrap_or_default is fine.
        dfn_core::api::call_with_cleanup(id, method, dfn_candid::candid_multi_arity, args)
            .await
            .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }

    async fn call_bytes_with_cleanup(
        id: CanisterId,
        method: &str,
        args: &[u8],
    ) -> Result<Vec<u8>, (i32, String)> {
        dfn_core::api::call_bytes_with_cleanup(id, method, args, dfn_core::api::Funds::zero())
            .await
            .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }

    fn spawn_future<F: 'static + Future<Output = ()>>(future: F) {
        dfn_core::api::futures::spawn(future);
    }

    fn canister_version() -> u64 {
        dfn_core::api::canister_version()
    }
}

pub struct CdkRuntime;

/// Translates a failed [`ic_cdk`] call into the `(reject code, message)` pair
/// that NNS & SNS canisters report to their callers.
///
/// The match is deliberately exhaustive (rather than using a catch-all arm) so
/// that a new [`IcCdkCallError`] variant forces us to revisit this mapping
/// instead of silently misclassifying it.
pub fn into_reject_code_and_message(err: IcCdkCallError) -> (i32, String) {
    match err {
        // The system (or the callee) already rejected the call and assigned a reject
        // code; surface it unchanged.
        IcCdkCallError::CallRejected(rejected) => (
            rejected.raw_reject_code() as i32,
            rejected.reject_message().to_string(),
        ),
        // The callee replied, but its response did not decode into the expected type,
        // so it did not honor its interface: treat it as a canister-side error.
        IcCdkCallError::CandidDecodeFailed(err) => {
            (RejectCode::CanisterError as i32, err.to_string())
        }
        // The call was not performed because this canister's liquid cycles balance
        // was too low. The protocol itself classifies an insufficient cycles balance
        // as `SysTransient` (both as the return value of `ic0.call_perform` and in
        // `ic-error-types`), so mirror that here rather than remapping it.
        IcCdkCallError::InsufficientLiquidCycleBalance(err) => {
            (RejectCode::SysTransient as i32, err.to_string())
        }
        // `ic0.call_perform` could not enqueue the call (e.g. a full output queue),
        // a transient system condition that a later retry may clear.
        IcCdkCallError::CallPerformFailed(err) => {
            (RejectCode::SysTransient as i32, err.to_string())
        }
    }
}

#[async_trait]
impl Runtime for CdkRuntime {
    // This method does not do clean up.
    async fn call_without_cleanup<In, Out>(
        _id: CanisterId,
        _method: &str,
        _args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        unimplemented!("There is no implementation of CdkRuntime that does not cleanup");
    }

    async fn call_with_cleanup<In, Out>(
        id: CanisterId,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        let principal_id = PrincipalId::from(id);
        Call::unbounded_wait(principal_id.into(), method)
            .with_args(&args)
            .await
            .map_err(IcCdkCallError::from)
            .and_then(|response| response.candid_tuple().map_err(IcCdkCallError::from))
            .map_err(into_reject_code_and_message)
    }

    async fn call_bytes_with_cleanup(
        id: CanisterId,
        method: &str,
        args: &[u8],
    ) -> Result<Vec<u8>, (i32, String)> {
        let principal_id = PrincipalId::from(id);
        Call::unbounded_wait(principal_id.into(), method)
            .with_raw_args(args)
            .await
            .map(|response| response.into_bytes())
            .map_err(|err| into_reject_code_and_message(err.into()))
    }

    fn spawn_future<F: 'static + Future<Output = ()>>(future: F) {
        ic_cdk::futures::spawn_017_compat(future);
    }

    fn canister_version() -> u64 {
        ic_cdk::api::canister_version()
    }
}
