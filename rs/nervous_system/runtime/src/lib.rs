use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use ic_base_types::{CanisterId, PrincipalId};
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
}

pub struct CdkRuntime;

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
        ic_cdk::api::call::call(principal_id.into(), method, args)
            .await
            .map_err(|(code, msg)| (code as i32, msg))
    }

    async fn call_bytes_with_cleanup(
        id: CanisterId,
        method: &str,
        args: &[u8],
    ) -> Result<Vec<u8>, (i32, String)> {
        let principal_id = PrincipalId::from(id);
        ic_cdk::api::call::call_raw(principal_id.into(), method, args, 0)
            .await
            .map_err(|(code, msg)| (code as i32, msg))
    }

    fn spawn_future<F: 'static + Future<Output = ()>>(future: F) {
        ic_cdk::spawn(future);
    }
}
