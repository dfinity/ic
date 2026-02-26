use crate::{
    pb::v1::{GovernanceError, TakeCanisterSnapshot, Topic},
    proposals::{call_canister::CallCanister, invalid_proposal_error, topic_to_manage_canister},
};
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_handler_root_interface::TakeCanisterSnapshotRequest;

impl TakeCanisterSnapshot {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        self.valid_canister_id()?;
        Ok(())
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        Ok(topic_to_manage_canister(&canister_id))
    }

    fn valid_canister_id(&self) -> Result<CanisterId, GovernanceError> {
        let canister_principal_id = self
            .canister_id
            .ok_or(invalid_proposal_error("Canister ID is required"))?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|_| invalid_proposal_error("Invalid canister ID"))?;

        Ok(canister_id)
    }
}

impl CallCanister for TakeCanisterSnapshot {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "take_canister_snapshot"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let args = convert_take_canister_snapshot_from_proposal_to_root_request(self)?;
        Encode!(&args)
            .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {e}")))
    }
}

pub fn convert_take_canister_snapshot_from_proposal_to_root_request(
    original: &TakeCanisterSnapshot,
) -> Result<TakeCanisterSnapshotRequest, GovernanceError> {
    let TakeCanisterSnapshot {
        replace_snapshot,
        canister_id: _,
    } = original.clone();

    let canister_id = PrincipalId::from(original.valid_canister_id()?);

    Ok(TakeCanisterSnapshotRequest {
        canister_id,
        replace_snapshot,
    })
}

#[cfg(test)]
#[path = "take_canister_snapshot_tests.rs"]
mod tests;
