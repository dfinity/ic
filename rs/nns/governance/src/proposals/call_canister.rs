use crate::pb::v1::GovernanceError;

use ic_base_types::CanisterId;

/// A trait for proposal types that simply calls a canister method with a payload.
pub trait CallCanister {
    /// Returns the target canister ID and method to call for proposal execution.
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError>;
    /// Returns the payload to send to the target canister.
    fn payload(&self) -> Result<Vec<u8>, GovernanceError>;
}

// TODO: impl CallCanister for ExecuteNnsFunction
