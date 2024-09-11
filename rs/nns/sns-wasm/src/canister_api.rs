use async_trait::async_trait;
use ic_base_types::{PrincipalId, SubnetId};
use ic_types::{CanisterId, Cycles};

use crate::pb::v1::SnsCanisterType;

#[async_trait]
pub trait CanisterApi {
    /// Get the CanisterId of the running canister
    fn local_canister_id(&self) -> CanisterId;

    /// Create a canister on a subnet with cycles assigned to a given controller.
    async fn create_sns_canister(
        &self,
        target_subnet: SubnetId,
        controller_id: PrincipalId,
        cycles: Cycles,
        canister_type: SnsCanisterType,
    ) -> Result<CanisterId, String>;

    /// Delete a canister that has been created
    async fn delete_canister(&self, canister: CanisterId) -> Result<(), String>;

    /// Install a WASM on a given canister (which must be controlled by this canister)
    async fn install_wasm(
        &self,
        target_canister: CanisterId,
        wasm: Vec<u8>,
        init_payload: Vec<u8>,
    ) -> Result<(), String>;

    /// Set the controllers for a given canister (this canister, SNS-WASMs, must currently control it)
    async fn set_controllers(
        &self,
        canister: CanisterId,
        controllers: Vec<PrincipalId>,
    ) -> Result<(), String>;

    /// Return cycles available from the canister's own balance, or error if not enough
    fn this_canister_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String>;

    /// Return the cycles available, or fail if insufficient cycles are available.
    fn message_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String>;

    /// Accept Some(number) of cycles, or if no cycles are given (i.e. None), accept all available cycles in the message
    fn accept_message_cycles(&self, cycles: Option<u64>) -> Result<u64, String>;

    /// Send cycles to another canister
    async fn send_cycles_to_canister(
        &self,
        target_canister: CanisterId,
        cycles: u64,
    ) -> Result<(), String>;
}
