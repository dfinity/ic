use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord;
use ic_registry_keys::make_standard_engine_replica_version_record_key;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use prost::Message;
use serde::Serialize;

/// Changes what replica version(s) are run by engines.
///
/// (Engines are a special kind of subnet, new as of summer 2026).
///
/// An engine can override what this says by populating its
/// SubnetRecord.replica_version_id field. In practice, we expect such overrides
/// to be rare.
///
/// Calling this is how Governance executes corresponding proposals.
///
/// Two kinds of changes are allowed:
///
/// 1. Change deployment_progress (usually increase, but decrease is allowed).
/// 2. Start a new deployment.
///
/// The latter is only allowed if the previous/current deployment is complete
/// (deployment_progress == 1.0, or there is no previous deployment). The new
/// deployment must start where the previous one left off, i.e. the new
/// old_replica_version_id must match the current/old new_replica_version_id.
impl Registry {
    pub fn do_update_standard_engine_replica_version(
        &mut self,
        payload: UpdateStandardEngineReplicaVersionPayload,
    ) {
        println!("{LOG_PREFIX}do_update_standard_engine_replica_version: {payload:?}");

        let new_record = StandardEngineReplicaVersionRecord::try_from(payload).unwrap();

        self.check_new_standard_engine_replica_version_record_vs_old(&new_record);

        let upsert = new_record.into_upsert();

        // Note that this checks invariants, such as that the new and old
        // replica versions are actually elected.
        self.maybe_apply_mutation_internal(vec![upsert]);
    }

    /// Validates the transition per the rule described on
    /// `do_update_standard_engine_replica_version`; panics if new_record isn't one
    /// of the two allowed cases. If there is no current record, any new_record is
    /// allowed.
    fn check_new_standard_engine_replica_version_record_vs_old(
        &self,
        new_record: &StandardEngineReplicaVersionRecord,
    ) {
        let Some(old_record) = self.get_standard_engine_replica_version_record() else {
            println!(
                "{LOG_PREFIX}check_new_standard_engine_replica_version_record_vs_old: no current \
                StandardEngineReplicaVersionRecord found; allowing {new_record:?}",
            );
            return;
        };

        // Allow deployment_progress to change (in either direction), as long as
        // the version IDs are unchanged.
        if new_record.has_same_versions_as(&old_record) {
            return;
        }

        if old_record.deployment_progress < 1.0 {
            panic!(
                "Invalid StandardEngineReplicaVersionRecord transition: the current deployment \
                 is still in progress, so a new deployment cannot be started yet. Current \
                 record: {old_record:?}. Proposed new record: {new_record:?}.",
            );
        }

        // Based on deployment_progress, looks like we are starting a new deployment.
        // Here, we check the new old_replica_version_id.
        assert_eq!(
            new_record.old_replica_version_id, old_record.new_replica_version_id,
            "Invalid StandardEngineReplicaVersionRecord transition: cannot skip a version. The \
             next deployment's old_replica_version_id must equal the current deployment's \
             new_replica_version_id.",
        );
    }

    fn get_standard_engine_replica_version_record(
        &self,
    ) -> Option<StandardEngineReplicaVersionRecord> {
        self.get(
            make_standard_engine_replica_version_record_key().as_bytes(),
            self.latest_version(),
        )
        .map(|v| StandardEngineReplicaVersionRecord::decode(v.value.as_slice()).unwrap())
    }
}

trait StandardEngineReplicaVersionRecordExt {
    /// True if both records specify the same (old_replica_version_id,
    /// new_replica_version_id) pair (regardless of deployment_progress). If so,
    /// the new record is just adjusting deployment_progress.
    fn has_same_versions_as(&self, other: &Self) -> bool;

    /// Converts self into an upsert RegistryMutation (at the standard key).
    fn into_upsert(self) -> RegistryMutation;
}

impl StandardEngineReplicaVersionRecordExt for StandardEngineReplicaVersionRecord {
    fn has_same_versions_as(&self, other: &Self) -> bool {
        self.old_replica_version_id == other.old_replica_version_id
            && self.new_replica_version_id == other.new_replica_version_id
    }

    fn into_upsert(self) -> RegistryMutation {
        RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_standard_engine_replica_version_record_key().into_bytes(),
            value: self.encode_to_vec(),
        }
    }
}

impl TryFrom<UpdateStandardEngineReplicaVersionPayload> for StandardEngineReplicaVersionRecord {
    type Error = String;

    fn try_from(payload: UpdateStandardEngineReplicaVersionPayload) -> Result<Self, Self::Error> {
        let UpdateStandardEngineReplicaVersionPayload {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        } = payload;

        if !(0.0..=1.0).contains(&deployment_progress) {
            return Err(format!(
                "deployment_progress must be in the range [0.0, 1.0], got {}.",
                deployment_progress,
            ));
        }

        if new_replica_version_id == old_replica_version_id {
            return Err(format!(
                "new_replica_version_id and old_replica_version_id must be different, but both \
                 are '{new_replica_version_id}'.",
            ));
        }

        Ok(Self {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
        })
    }
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateStandardEngineReplicaVersionPayload {
    pub new_replica_version_id: String,
    pub old_replica_version_id: String,
    pub deployment_progress: f64,
    // Later, we could add force, which would override the transition
    // restrictions. But for now, there seems to be no point in doing that.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
    use ic_registry_keys::make_replica_version_key;
    use ic_registry_transport::insert;
    use lazy_static::lazy_static;
    use prost::Message;

    lazy_static! {
        // invariant_compliant_registry(0) + some elected replica versions.
        static ref REGISTRY: Registry = {
            let mut result = invariant_compliant_registry(0);

            for version in ["v1", "v2", "v3", "v4"] {
                result.maybe_apply_mutation_internal(vec![insert(
                    make_replica_version_key(version),
                    ReplicaVersionRecord {
                        release_package_sha256_hex: "".into(),
                        release_package_urls: vec![],
                        guest_launch_measurements: None,
                    }
                    .encode_to_vec(),
                )]);
            }

            result
        };
    }

    #[track_caller]
    fn assert_standard_engine_replica_version_record_eq(
        registry: &Registry,
        expected: StandardEngineReplicaVersionRecord,
    ) {
        let actual = registry
            .get_standard_engine_replica_version_record()
            .expect("failed to get standard engine replica version record");
        assert_eq!(actual, expected);
    }

    /// Since there is no previous record, the "transition" requirements are met
    /// trivially. Nevertheless, the "static" requirements still need to be met.
    /// To wit, progress is in [0.0, 1.0] and the two versions are different and
    /// elected.
    #[test]
    fn should_succeed_when_there_is_no_previous_record() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".to_string(),
                old_replica_version_id: "v1".to_string(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        assert_standard_engine_replica_version_record_eq(
            &registry,
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: "v2".to_string(),
                old_replica_version_id: "v1".to_string(),
                deployment_progress: 0.1,
            },
        );
    }

    #[test]
    fn should_allow_changing_deployment_progress_in_either_direction() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".to_string(),
                old_replica_version_id: "v1".to_string(),
                deployment_progress: 0.1,
            },
        );

        // deployment_progress bounces around wildly.
        for deployment_progress in [0.15, 0.9, 0.2, 1.0, 0.0] {
            // Step 2: Call the code under test.
            registry.do_update_standard_engine_replica_version(
                UpdateStandardEngineReplicaVersionPayload {
                    new_replica_version_id: "v2".into(),
                    old_replica_version_id: "v1".into(),
                    deployment_progress,
                },
            );

            // Step 3: Verify result(s).

            // Step 3.1: The previous statement did not panic, unlike many of
            // our tests.

            // Step 3.2: The contents of registry reflects the change we tried
            // to make.
            assert_standard_engine_replica_version_record_eq(
                &registry,
                StandardEngineReplicaVersionRecord {
                    new_replica_version_id: "v2".to_string(),
                    old_replica_version_id: "v1".to_string(),
                    deployment_progress,
                },
            );
        }
    }

    #[test]
    fn should_allow_starting_the_next_deployment_once_fully_deployed() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 1.1: v2 is fully deployed (previously, we were on Replica v1).
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: 1.0,
            },
        );

        // Step 2: Run the code under test. Start the next deployment: v2 -> v3.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v3".into(),
                old_replica_version_id: "v2".into(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).

        // Step 3.1: The previous statement did not panic, even though the
        // versions changed. This is allowed, because previously,
        // deployment_progress was 1.0. Furthermore, we are not "jumping the
        // gun"; more precisely, new old_replica_version_id ("v2") matches the
        // previous/current new_replica_version_id.

        // Step 3.2: The contents of registry reflects the change we tried to make.
        assert_standard_engine_replica_version_record_eq(
            &registry,
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: "v3".to_string(),
                old_replica_version_id: "v2".to_string(),
                deployment_progress: 0.1,
            },
        );
    }

    #[test]
    #[should_panic(expected = "the current deployment is still in progress")]
    fn should_panic_when_changing_versions_before_fully_deployed() {
        // Step 1: Prepare the world. Partially deploy v1 -> v2
        // (deployment_progress isn't 1.0 yet).
        let mut registry = REGISTRY.clone();
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: 0.9,
            },
        );

        // Step 2: Run the code under test. Try to upgrade engines from v2 to v3.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v3".into(),
                old_replica_version_id: "v2".into(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "cannot skip a version")]
    fn should_panic_when_skipping_a_version() {
        // Step 1: Prepare the world. Fully deploy v1 -> v2.
        let mut registry = REGISTRY.clone();
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: 1.0,
            },
        );

        // Step 2: Run the code under test. The new old_replica_version_id
        // ("v3") doesn't match the current/previous record's
        // new_replica_version_id ("v2"), which is supposed to be not allowed.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v4".into(),
                old_replica_version_id: "v3".into(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn should_panic_if_new_version_not_elected() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test. new_replica_version_id is
        // deliberately not one of REGISTRY's pre-elected versions.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "unelected_version".to_string(),
                old_replica_version_id: "v1".to_string(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn should_panic_if_old_version_not_elected() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test. old_replica_version_id is
        // deliberately not one of REGISTRY's pre-elected versions.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".to_string(),
                old_replica_version_id: "unelected_version".to_string(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "deployment_progress must be in the range [0.0, 1.0]")]
    fn should_panic_if_deployment_progress_is_too_large() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: 1.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "deployment_progress must be in the range [0.0, 1.0]")]
    fn should_panic_if_deployment_progress_is_too_small() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v2".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: -0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "must be different")]
    fn should_panic_if_new_and_old_versions_are_the_same() {
        // Step 1: Prepare the world.
        let mut registry = REGISTRY.clone();

        // Step 2: Run the code under test.
        registry.do_update_standard_engine_replica_version(
            UpdateStandardEngineReplicaVersionPayload {
                new_replica_version_id: "v1".into(),
                old_replica_version_id: "v1".into(),
                deployment_progress: 0.1,
            },
        );

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }
}
