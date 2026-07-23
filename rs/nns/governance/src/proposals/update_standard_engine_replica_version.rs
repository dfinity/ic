use crate::{
    pb::v1::{GovernanceError, SelfDescribingValue, Topic, UpdateStandardEngineReplicaVersion},
    proposals::{
        call_canister::CallCanister,
        invalid_proposal_error,
        self_describing::{DocumentedAction, ValueBuilder},
    },
};

use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_ids::is_potential_full_git_commit_id;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use registry_canister::mutations::do_update_standard_engine_replica_version::UpdateStandardEngineReplicaVersionPayload;

impl UpdateStandardEngineReplicaVersion {
    /// Passing this validation does NOT guarantee that Registry will accept the
    /// change. E.g. if at the time of proposal execution (or creation), one of
    /// the versions is not elected, then, no changes will be made in Registry.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        let Self {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        } = self;

        // Replica version IDs must be plausible full git commit IDs.
        if !is_potential_full_git_commit_id(new_replica_version_id) {
            return Err(invalid_proposal_error(&format!(
                "new_replica_version_id is not a 40 character hexidecimal string (it was {:?})",
                new_replica_version_id,
            )));
        }
        if !is_potential_full_git_commit_id(old_replica_version_id) {
            return Err(invalid_proposal_error(&format!(
                "old_replica_version_id is not a 40 character hexidecimal string (it was {:?})",
                old_replica_version_id,
            )));
        }

        // Replica version IDs must differ.
        if old_replica_version_id == new_replica_version_id {
            return Err(invalid_proposal_error(&format!(
                "new_replica_version_id and old_replica_version_id must not be equal (both were {:?})",
                new_replica_version_id,
            )));
        }

        // deployment_progress must be in the closed interval [0.0, 1.0].
        if !(0.0..=1.0).contains(deployment_progress) {
            return Err(invalid_proposal_error(&format!(
                "deployment_progress must be in the closed interval [0.0, 1.0], but got {}",
                deployment_progress,
            )));
        }

        Ok(())
    }

    pub fn valid_topic(&self) -> Topic {
        Topic::IcOsVersionDeployment
    }
}

impl CallCanister for UpdateStandardEngineReplicaVersion {
    type Reply = ();

    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((
            REGISTRY_CANISTER_ID,
            "update_standard_engine_replica_version",
        ))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let payload = UpdateStandardEngineReplicaVersionPayload::from(self.clone());

        Encode!(&payload)
            .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
    }
}

impl From<UpdateStandardEngineReplicaVersion> for UpdateStandardEngineReplicaVersionPayload {
    fn from(original: UpdateStandardEngineReplicaVersion) -> Self {
        let UpdateStandardEngineReplicaVersion {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        } = original;

        Self {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        }
    }
}

impl DocumentedAction for UpdateStandardEngineReplicaVersion {
    const NAME: &'static str = "Update Standard Engine Replica Version";
    const DESCRIPTION: &'static str = "Change what replica version(s) are run by Cloud Engines.";
}

impl From<UpdateStandardEngineReplicaVersion> for SelfDescribingValue {
    fn from(original: UpdateStandardEngineReplicaVersion) -> Self {
        let UpdateStandardEngineReplicaVersion {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        } = original;

        ValueBuilder::new()
            .add_field("new_replica_version_id", new_replica_version_id)
            .add_field("old_replica_version_id", old_replica_version_id)
            .add_field("deployment_progress", deployment_progress.to_string())
            .build()
    }
}

#[cfg(test)]
#[path = "./update_standard_engine_replica_version_tests.rs"]
mod tests;
