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

    /// Install a WASM on a given canister (which must be controlled by this canister)
    async fn install_wasm(
        &self,
        target_canister: CanisterId,
        wasm: Vec<u8>,
        init_payload: Vec<u8>,
    ) -> Result<(), String>;

    /// Set the controller for a given canister (we must currently control it)
    async fn set_controller(
        &self,
        canister: CanisterId,
        controller: PrincipalId,
    ) -> Result<(), String>;
}
