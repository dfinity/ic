use async_trait::async_trait;
use ic_base_types::CanisterId;
/// A general trait for the environment in which governance is running.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    /// Calls another canister. The return value indicates whether the call can be successfully
    /// initiated. If initiating the call is successful, the call could later be rejected by the
    /// remote canister. In CanisterEnv (the production implementation of this trait), to
    /// distinguish between whether the remote canister replies or rejects,
    /// set_proposal_execution_status is called (asynchronously). Therefore, the caller of
    /// call_canister should not call set_proposal_execution_status if call_canister returns Ok,
    /// because the call could fail later.
    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<
        /* reply: */ Vec<u8>,
        (
            /* error_code: */ Option<i32>,
            /* message: */ String,
        ),
    >;

    /// Returns the PrincipalId of the canister implementing the Environment trait.
    fn canister_id(&self) -> CanisterId;
}
