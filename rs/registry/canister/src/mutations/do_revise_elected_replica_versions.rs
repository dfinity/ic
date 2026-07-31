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

        if let Some(version) = payload.replica_version_to_elect.as_ref() {
            assert!(
                !versions_to_remove.contains(version),
                "{LOG_PREFIX}ReviseElectedGuestosVersionsPayload cannot elect and unelect the same version.",
            );

            mutations.push(
                // Register the new version (that is, insert the new ReplicaVersionRecord)
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Insert as i32,
                    key: make_replica_version_key(version).as_bytes().to_vec(),
                    value: ReplicaVersionRecord {
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

    /// The SEV-SNP measurements that belong to this release
    pub guest_launch_measurements: Option<GuestLaunchMeasurements>,

    /// Version IDs. These can be anything, they have no semantics.
    pub replica_versions_to_unelect: Vec<String>,
}

impl ReviseElectedGuestosVersionsPayload {
    pub fn is_electing_a_version(&self) -> Result<bool, String> {
        let elect_params = [
            self.replica_version_to_elect.as_ref(),
            self.release_package_sha256_hex.as_ref(),
            self.release_package_urls.first(),
        ];

        if elect_params.iter().all(|p| p.is_some()) {
            return Ok(true);
        }

        if elect_params.iter().all(|p| p.is_none()) {
            return Ok(false);
        }

        Err("All parameters to elect a version have to be either set or unset.".into())
    }

    pub fn is_unelecting_a_version(&self) -> bool {
        !self.replica_versions_to_unelect.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.is_electing_a_version()? || self.is_unelecting_a_version() {
            Ok(())
        } else {
            Err("At least one version has to be elected or unelected.".into())
        }
    }
}
