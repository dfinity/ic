use crate::invariants::common::{InvariantCheckError, RegistrySnapshot, get_value_from_snapshot};
use ic_protobuf::registry::standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord;
use ic_registry_keys::make_standard_engine_replica_version_record_key;

/// A predicate on the StandardEngineReplicaVersionRecord, if one is present in
/// the registry snapshot.
///
/// Currently, this checks that:
///
/// 1. deployment_progress is in the range [0.0, 1.0].
/// 2. new_replica_version_id and old_replica_version_id are different.
///
/// It is checked elsewhere that both versions are elected, so that is not
/// repeated here.
pub(crate) fn check_standard_engine_replica_version_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let Some(record) = get_value_from_snapshot::<StandardEngineReplicaVersionRecord>(
        snapshot,
        make_standard_engine_replica_version_record_key(),
    ) else {
        // If there is no record yet, then we are trivially valid.
        return Ok(());
    };

    let StandardEngineReplicaVersionRecord {
        new_replica_version_id,
        old_replica_version_id,
        deployment_progress,
    } = record;

    // Inspect deployment_progress.
    if !(0.0..=1.0).contains(&deployment_progress) {
        return Err(InvariantCheckError {
            msg: format!(
                "StandardEngineReplicaVersionRecord.deployment_progress must be in the range \
                 [0.0, 1.0], got {deployment_progress}.",
            ),
            source: None,
        });
    }

    // Replica versions must be different.
    if new_replica_version_id == old_replica_version_id {
        return Err(InvariantCheckError {
            msg: format!(
                "Versions in StandardEngineReplicaVersionRecord must be different. \
                 Got {new_replica_version_id} vs {old_replica_version_id}.",
            ),
            source: None,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::test_helpers::invariant_compliant_registry, registry::Registry};
    use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
    use ic_registry_keys::make_replica_version_key;
    use ic_registry_transport::insert;
    use lazy_static::lazy_static;
    use prost::Message;

    // Replica version IDs are git commit IDs (pointing to the source code used
    // to build the Replica).
    const REPLICA_VERSION_ID_1: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";
    const REPLICA_VERSION_ID_2: &str = "63d086714a1e2bc6b0615008d5582f527d554cd3";

    lazy_static! {
        // Fixture for tests below.
        static ref REGISTRY: Registry = {
            let mut result = invariant_compliant_registry(0);

            // Elect a couple of replica versions.
            let mutations = [
                REPLICA_VERSION_ID_1.to_string(),
                REPLICA_VERSION_ID_2.to_string(),
            ]
            .into_iter()
            .map(|v| {
                insert(
                    make_replica_version_key(v).as_bytes(),
                    ReplicaVersionRecord::default().encode_to_vec(),
                )
            })
            .collect();
            result.maybe_apply_mutation_internal(mutations);

            result
        };
    }

    #[test]
    #[should_panic(expected = "deployment_progress must be in the range [0.0, 1.0]")]
    fn panic_when_deployment_progress_too_large() {
        // Step 1: Prepare the world.
        // Already done above, in the definition of  REGISTRY itself.

        // Step 2: Run the code under test. Try to set deployment_progress
        // outside of [0.0, 1.0].
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            old_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
            deployment_progress: 1.1,
        }
        .encode_to_vec();
        let mutation = vec![insert(key.as_bytes(), value)];
        REGISTRY.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "deployment_progress must be in the range [0.0, 1.0]")]
    fn panic_when_deployment_progress_too_small() {
        // Step 1: Prepare the world.
        // Already done above, in the definition of  REGISTRY itself.

        // Step 2: Run the code under test. Try to set deployment_progress
        // outside of [0.0, 1.0].
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            old_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
            deployment_progress: -0.1,
        }
        .encode_to_vec();
        let mutation = vec![insert(key.as_bytes(), value)];
        REGISTRY.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Versions in StandardEngineReplicaVersionRecord must be different")]
    fn panic_when_new_and_old_versions_are_the_same() {
        // Step 1: Prepare the world.
        // Already done above, in the definition of  REGISTRY itself.

        // Step 2: Run the code under test. Try to go from one version to
        // itself.
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            deployment_progress: 0.1,
        }
        .encode_to_vec();
        let mutation = vec![insert(key.as_bytes(), value)];
        REGISTRY.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }
}
