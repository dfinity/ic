use super::*;

use crate::{
    pb::v1::{
        SelfDescribingValue as SelfDescribingValuePb, UpdateStandardEngineReplicaVersion,
        governance_error::ErrorType, proposal::Action,
    },
    proposals::ValidProposalAction,
};

use candid::Decode;
use ic_nns_governance_api::SelfDescribingValue;
use lazy_static::lazy_static;
use maplit::hashmap;

lazy_static! {
    static ref VALID_UPDATE: UpdateStandardEngineReplicaVersion =
        UpdateStandardEngineReplicaVersion {
            new_replica_version_id: "1234567890".repeat(4),
            old_replica_version_id: "abcd".repeat(10),
            deployment_progress: 0.1,
        };
}

#[test]
fn test_valid_update_standard_engine_replica_version() {
    assert_eq!(VALID_UPDATE.validate(), Ok(()));
}

#[track_caller]
fn assert_invalid_update(update: UpdateStandardEngineReplicaVersion, keywords: &[&str]) {
    let error = update.validate().unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);

    for keyword in keywords {
        let error_message = error.error_message.to_lowercase();
        assert!(
            error_message.contains(keyword),
            "{keyword} not found in {error_message:#?}"
        );
    }
}

#[test]
fn test_invalid_update_standard_engine_replica_version() {
    // Reject garbage replica version IDs.
    assert_invalid_update(
        UpdateStandardEngineReplicaVersion {
            new_replica_version_id: "g@rbage".to_string(),
            ..VALID_UPDATE.clone()
        },
        &["new_replica_version_id", "40", "hexadecimal"],
    );
    assert_invalid_update(
        UpdateStandardEngineReplicaVersion {
            old_replica_version_id: "not_a_git_commit_id".to_string(),
            ..VALID_UPDATE.clone()
        },
        &["old_replica_version_id", "40", "hexadecimal"],
    );

    // Replica versions must differ.
    assert_invalid_update(
        UpdateStandardEngineReplicaVersion {
            old_replica_version_id: VALID_UPDATE.new_replica_version_id.clone(),
            ..VALID_UPDATE.clone()
        },
        &["new_replica_version_id", "old_replica_version_id", "equal"],
    );

    // deployment_progress out of range.
    assert_invalid_update(
        UpdateStandardEngineReplicaVersion {
            deployment_progress: 1.1,
            ..VALID_UPDATE.clone()
        },
        &["deployment_progress", "[0.0, 1.0]"],
    );
    assert_invalid_update(
        UpdateStandardEngineReplicaVersion {
            deployment_progress: -0.1,
            ..VALID_UPDATE.clone()
        },
        &["deployment_progress", "[0.0, 1.0]"],
    );
}

#[test]
fn test_update_standard_engine_replica_version_boundary_progress_values_are_valid() {
    assert_eq!(
        UpdateStandardEngineReplicaVersion {
            deployment_progress: 0.0,
            ..VALID_UPDATE.clone()
        }
        .validate(),
        Ok(())
    );

    assert_eq!(
        UpdateStandardEngineReplicaVersion {
            deployment_progress: 1.0,
            ..VALID_UPDATE.clone()
        }
        .validate(),
        Ok(())
    );
}

#[test]
fn test_update_standard_engine_replica_version_topic_and_dispatch() {
    assert_eq!(VALID_UPDATE.valid_topic(), Topic::IcOsVersionDeployment);
    assert_eq!(
        VALID_UPDATE.canister_and_function(),
        Ok((
            REGISTRY_CANISTER_ID,
            "update_standard_engine_replica_version"
        ))
    );

    let decoded_payload = Decode!(
        &VALID_UPDATE.payload().unwrap(),
        UpdateStandardEngineReplicaVersionPayload
    )
    .unwrap();
    assert_eq!(
        decoded_payload,
        UpdateStandardEngineReplicaVersionPayload {
            new_replica_version_id: VALID_UPDATE.new_replica_version_id.clone(),
            old_replica_version_id: VALID_UPDATE.old_replica_version_id.clone(),
            deployment_progress: VALID_UPDATE.deployment_progress,
        }
    );
}

#[test]
fn test_update_standard_engine_replica_version_to_self_describing() {
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(VALID_UPDATE.clone()));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "new_replica_version_id".to_string() =>
                SelfDescribingValue::from(VALID_UPDATE.new_replica_version_id.as_str()),
            "old_replica_version_id".to_string() =>
                SelfDescribingValue::from(VALID_UPDATE.old_replica_version_id.as_str()),
            "deployment_progress".to_string() =>
                SelfDescribingValue::from(VALID_UPDATE.deployment_progress.to_string().as_str()),
        })
    );
}

#[test]
fn test_valid_proposal_action_conversion() {
    let action = ValidProposalAction::try_from(Some(Action::UpdateStandardEngineReplicaVersion(
        VALID_UPDATE.clone(),
    )))
    .unwrap();

    assert_eq!(
        action,
        ValidProposalAction::UpdateStandardEngineReplicaVersion(VALID_UPDATE.clone())
    );
}
