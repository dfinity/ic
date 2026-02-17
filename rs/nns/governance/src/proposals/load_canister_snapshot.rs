use crate::{
    pb::v1::{
        GovernanceError, LoadCanisterSnapshot, SelfDescribingValue, Topic,
        governance_error::ErrorType,
    },
    proposals::{
        call_canister::CallCanister, self_describing::LocallyDescribableProposalAction,
        topic_to_manage_canister,
    },
};
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_handler_root_interface::LoadCanisterSnapshotRequest;

impl LoadCanisterSnapshot {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !crate::are_canister_snapshot_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "LoadCanisterSnapshot proposals are not enabled yet.",
            ));
        }

        let Self {
            canister_id,
            snapshot_id,
        } = self;

        let mut defects = vec![];

        match validate_canister_id(*canister_id) {
            Ok(_canister_id) => (),
            Err(canister_id_defects) => {
                defects.extend(canister_id_defects);
            }
        };

        if snapshot_id.is_empty() {
            defects.push("Snapshot ID cannot be empty".to_string());
        }

        if !defects.is_empty() {
            return Err(defects_to_governance_error(defects));
        }

        Ok(())
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id =
            validate_canister_id(self.canister_id).map_err(defects_to_governance_error)?;

        Ok(topic_to_manage_canister(&canister_id))
    }
}

impl CallCanister for LoadCanisterSnapshot {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "load_canister_snapshot"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let Self {
            canister_id,
            snapshot_id,
        } = self.clone();

        let canister_id = validate_canister_id(canister_id).map_err(defects_to_governance_error)?;
        let canister_id = PrincipalId::from(canister_id);

        let request = LoadCanisterSnapshotRequest {
            canister_id,
            snapshot_id,
        };

        Encode!(&request).map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Failed to encode LoadCanisterSnapshotArgs: {}", e),
            )
        })
    }
}

fn validate_canister_id(
    canister_id: Option<PrincipalId>,
) -> Result<CanisterId, /* defects*/ Vec<String>> {
    let Some(canister_id) = canister_id else {
        return Err(vec!["Canister ID is required".to_string()]);
    };

    CanisterId::try_from(canister_id).map_err(|e| vec![format!("Invalid canister ID: {}", e)])
}

fn defects_to_governance_error(defects: Vec<String>) -> GovernanceError {
    crate::proposals::invalid_proposal_error(&defects.join("; "))
}

impl LocallyDescribableProposalAction for LoadCanisterSnapshot {
    const TYPE_NAME: &'static str = "Load Canister Snapshot";
    const TYPE_DESCRIPTION: &'static str = "Load a snapshot created by a Take Canister Snapshot \
        proposal into a canister controlled by the NNS. Loading a snapshot replaces the \
        canister's current stable memory, heap memory, data, and Wasm module with what was saved \
        in the snapshot, rolling the canister back to that earlier state.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        SelfDescribingValue::from(self.clone())
    }
}

#[cfg(test)]
#[path = "load_canister_snapshot_tests.rs"]
mod tests;
