use std::collections::BTreeSet;

use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_registry_keys::make_replica_version_key;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Update the elected replica versions by:
    /// a) Adding a new replica version to the registry
    ///
    /// b) Removing specified replica versions from the registry
    ///
    /// This method is called by the governance canister, after a proposal
    /// for updating the elected replica versions has been accepted.
    pub fn do_revise_elected_guestos_versions(
        &mut self,
        payload: ReviseElectedGuestosVersionsPayload,
    ) {
        println!("{LOG_PREFIX}do_revise_elected_replica_versions: {payload:?}");
        payload
            .validate()
            .map_err(|e| panic!("{LOG_PREFIX}Failed to validate payload: {e}"))
            .unwrap();

        let versions_to_remove = BTreeSet::from_iter(payload.replica_versions_to_unelect);

        // Remove the unelected versions (that is, delete their ReplicaVersionRecords)
        let mut mutations: Vec<RegistryMutation> = versions_to_remove
            .iter()
            .map(|v| RegistryMutation {
                mutation_type: registry_mutation::Type::Delete as i32,
                key: make_replica_version_key(v).as_bytes().to_vec(),
                value: vec![],
            })
            .collect();

        if let Some(version) = payload.replica_version_to_elect {
            assert!(
                !versions_to_remove.contains(&version),
                "{LOG_PREFIX}ReviseElectedGuestosVersionsPayload cannot elect and unelect the same version.",
            );

            mutations.push(
                // Register the new version (that is, insert the new ReplicaVersionRecord)
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Insert as i32,
                    key: make_replica_version_key(&version).as_bytes().to_vec(),
                    value: ReplicaVersionRecord {
                        replica_version_id: version,
                        release_package_sha256_hex: payload
                            .release_package_sha256_hex
                            .unwrap_or_else(|| {
                                panic!("{LOG_PREFIX}Release package hash has to be provided")
                            }),
                        release_package_urls: payload.release_package_urls,
                        guest_launch_measurements: payload.guest_launch_measurements,
                    }
                    .encode_to_vec(),
                },
            );
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to update elected replica versions.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from a
/// ReviseElectedGuestosVersionsPayload, it is possible to construct a ReplicaVersionRecord.
///
/// See /rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct ReviseElectedGuestosVersionsPayload {
    /// Version ID. This can be anything, it has not semantics. The reason it is
    /// part of the payload is that it will be needed in the subsequent step
    /// of upgrading individual subnets.
    pub replica_version_to_elect: Option<String>,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_urls'
    pub release_package_sha256_hex: Option<String>,

    /// The URLs against which a HTTP GET request will return the same release
    /// package that corresponds to this version
    pub release_package_urls: Vec<String>,

    /// The SEV-SNP measurements that belong to this release. Required (and must
    /// be valid) whenever a version is elected.
    pub guest_launch_measurements: Option<GuestLaunchMeasurements>,

    /// Version IDs. These can be anything, they have no semantics.
    pub replica_versions_to_unelect: Vec<String>,
}

impl ReviseElectedGuestosVersionsPayload {
    /// Returns true if all required fields for electing a version are Some and false
    /// if all the fields are None. In all other cases, it returns an Err as
    ///  the payload is malformed (e.g. some fields are set and some are not).
    pub fn is_electing_a_version(&self) -> Result<bool, String> {
        let elect_params = [
            (
                "replica_version_to_elect",
                self.replica_version_to_elect.is_some(),
            ),
            (
                "release_package_sha256_hex",
                self.release_package_sha256_hex.is_some(),
            ),
            (
                "release_package_urls",
                !self.release_package_urls.is_empty(),
            ),
            (
                "guest_launch_measurements",
                self.guest_launch_measurements.is_some(),
            ),
        ];

        if elect_params.iter().all(|(_, is_set)| *is_set) {
            return Ok(true);
        }

        if elect_params.iter().all(|(_, is_set)| !is_set) {
            return Ok(false);
        }

        // Leave breadcrumbs: which parameters were missing.
        let mut unset_params = Vec::new();
        for (name, is_set) in elect_params {
            if !is_set {
                unset_params.push(name);
            }
        }

        Err(format!(
            "All parameters to elect a version have to be either set or unset. \
             Missing parameters: {unset_params:?}."
        ))
    }

    pub fn is_unelecting_a_version(&self) -> bool {
        !self.replica_versions_to_unelect.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        let is_making_a_change = self.is_electing_a_version()? || self.is_unelecting_a_version();
        if !is_making_a_change {
            return Err("At least one version has to be elected or unelected.".into());
        }

        // The ReplicaVersionRecord invariant checks this as well.
        // Deliberately checking it here too, as ic-admin calls validate before
        // submitting a proposal: that way, malformed measurements are caught while the
        // proposal is being composed, rather than when an adopted proposal is executed.
        if let Some(guest_launch_measurements) = self.guest_launch_measurements.as_ref() {
            guest_launch_measurements.validate().map_err(|defects| {
                format!("The provided guest_launch_measurements are invalid: {defects:?}")
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurementMetadata,
    };
    use lazy_static::lazy_static;

    const REPLICA_VERSION_ID: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";
    const RELEASE_PACKAGE_SHA256_HEX: &str =
        "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D";
    const RELEASE_PACKAGE_URL: &str = "http://release_package.tar.zst";

    lazy_static! {
        static ref GUEST_LAUNCH_MEASUREMENTS: GuestLaunchMeasurements = GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                // An SEV-SNP measurement is exactly 48 bytes long. The value
                // itself does not matter here.
                measurement: vec![0x42; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("foo=bar".to_string()),
                    vcpu_type: None,
                }),
            }],
        };

        /// A payload that elects one version, and that has everything electing a
        /// version requires. The tests below start from this and vary the launch
        /// measurements, because that is what they are about.
        static ref ELECT_PAYLOAD: ReviseElectedGuestosVersionsPayload =
            ReviseElectedGuestosVersionsPayload {
                replica_version_to_elect: Some(REPLICA_VERSION_ID.to_string()),
                release_package_sha256_hex: Some(RELEASE_PACKAGE_SHA256_HEX.to_string()),
                release_package_urls: vec![RELEASE_PACKAGE_URL.to_string()],
                guest_launch_measurements: Some(GUEST_LAUNCH_MEASUREMENTS.clone()),
                replica_versions_to_unelect: vec![],
            };
    }

    #[test]
    fn test_electing_a_version_with_launch_measurements_is_valid() {
        let payload = ELECT_PAYLOAD.clone();
        let result = payload.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_electing_a_version_without_launch_measurements_is_rejected() {
        // Step 1: Prepare the world.
        let mut payload = ELECT_PAYLOAD.clone();
        payload.guest_launch_measurements = None;

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s). The defect names the missing parameter.
        let defect = result.unwrap_err().to_lowercase();
        for key_word in [
            "all parameters",
            r#"missing parameters: ["guest_launch_measurements"]"#,
        ] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }

    #[test]
    fn test_electing_a_version_with_empty_launch_measurements_is_rejected() {
        // Step 1: Prepare the world.
        let mut payload = ELECT_PAYLOAD.clone();
        payload.guest_launch_measurements = Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![],
        });

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s).
        let defect = result.unwrap_err().to_lowercase();
        for key_word in ["guest_launch_measurements", "empty"] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }

    #[test]
    fn test_electing_a_version_with_invalid_launch_measurement_is_rejected() {
        // Step 1: Prepare the world.
        let mut payload = ELECT_PAYLOAD.clone();
        payload.guest_launch_measurements = Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                // The measurement is too short, it is supposed to be 48 bytes long.
                measurement: vec![0x42; 3],
                metadata: None,
            }],
        });

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s).
        let defect = result.unwrap_err().to_lowercase();
        for key_word in ["guest_launch_measurements", "48 bytes"] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }

    #[test]
    fn test_unelecting_a_version_without_electing_one_is_valid() {
        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: None,
            // None is Ok (in fact, required), because not electing a version.
            guest_launch_measurements: None,
            // Since not electing a version, we must at least unelect one to
            // avoid being a no-op, which is not allowed.
            replica_versions_to_unelect: vec![REPLICA_VERSION_ID.to_string()],
            release_package_sha256_hex: None,
            release_package_urls: vec![],
        };

        let result = payload.validate();

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_unelecting_a_version_with_partial_election_parameters_is_rejected() {
        // Step 1: Prepare the world.
        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: None,
            // The previous test shows that None does NOT explode. This test shows
            // that Some DOES explode.
            guest_launch_measurements: Some(GUEST_LAUNCH_MEASUREMENTS.clone()),
            replica_versions_to_unelect: vec![REPLICA_VERSION_ID.to_string()],
            ..Default::default()
        };

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s). The measurements are the only election
        // parameter that is set, so the other three are reported as missing.
        let defect = result.unwrap_err().to_lowercase();
        for key_word in [
            "all parameters",
            "replica_version_to_elect",
            "release_package_sha256_hex",
            "release_package_urls",
        ] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }

    #[test]
    fn test_no_op_is_rejected() {
        // Step 1: Prepare the world.
        let payload = ReviseElectedGuestosVersionsPayload::default();

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s).
        let defect = result.unwrap_err().to_lowercase();
        for key_word in ["at least one version", "elected or unelected"] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }

    #[test]
    fn test_incomplete_election_parameters_are_rejected() {
        // Step 1: Prepare the world.
        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: Some(REPLICA_VERSION_ID.to_string()),
            guest_launch_measurements: Some(GUEST_LAUNCH_MEASUREMENTS.clone()),
            // release_package_* fields are missing.
            ..Default::default()
        };

        // Step 2: Run the code under test.
        let result = payload.validate();

        // Step 3: Verify result(s).
        let defect = result.unwrap_err().to_lowercase();
        for key_word in [
            "all parameters",
            "release_package_sha256_hex",
            "release_package_urls",
        ] {
            assert!(defect.contains(key_word), "{key_word} not in {defect}");
        }
    }
}
