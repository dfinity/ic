use async_trait::async_trait;
use ic_base_types::{PrincipalId, SubnetId};
use ic_types::{CanisterId, Cycles};

#[async_trait]
pub trait CanisterApi {
    /// Get the CanisterId of the running canister
    fn local_canister_id(&self) -> CanisterId;

    /// Create a canister on a subnet with cycles assigned to a given controller.
    async fn create_canister(
        &self,
        target_subnet: SubnetId,
        controller_id: PrincipalId,
        cycles: Cycles,
    ) -> Result<CanisterId, String>;
}
