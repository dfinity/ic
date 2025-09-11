use std::collections::BTreeSet;

use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_protobuf::registry::{
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    subnet::v1::{SubnetListRecord, SubnetRecord},
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_replica_version_key, make_subnet_list_record_key,
    make_subnet_record_key, make_unassigned_nodes_config_record_key,
};
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Update the elected replica versions by:
    /// a) Adding a new replica version to the registry and blessing it, i.e.,
    ///    adding the version's ID to the list of blessed replica versions.
    ///
    /// b) Removing specified replica versions from the registry and retiring them, i.e.,
    ///    removing the versions' IDs from the list of blessed replica versions.
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

        let mut versions = self.remove_blessed_versions_or_panic(&versions_to_remove);

        if let Some(version) = payload.replica_version_to_elect.as_ref() {
            assert!(
                !versions_to_remove.contains(version),
                "{LOG_PREFIX}ReviseElectedGuestosVersionsPayload cannot elect and unelect the same version.",
            );

            versions.push(version.clone());
            println!("{LOG_PREFIX}Blessed versions after append: {versions:?}");

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

        mutations.push(
            // Update the list of blessed versions
            RegistryMutation {
                mutation_type: registry_mutation::Type::Upsert as i32,
                key: make_blessed_replica_versions_key().as_bytes().to_vec(),
                value: BlessedReplicaVersions {
                    blessed_version_ids: versions,
                }
                .encode_to_vec(),
            },
        );

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    /// Try to remove the given versions from registry. Panic if any of them are in
    /// use by a subnet or unassigned nodes. Return the list of blessed version IDs
    /// that remain after removal.
    pub fn remove_blessed_versions_or_panic(
        &self,
        versions_to_remove: &BTreeSet<String>,
    ) -> Vec<String> {
        let version = self.latest_version();
        // Get the current list
        let blessed_key = make_blessed_replica_versions_key();
        let before_removal = self
            .get(blessed_key.as_bytes(), version)
            .map(|reg_value| {
                BlessedReplicaVersions::decode(reg_value.value.as_slice())
                    .unwrap()
                    .blessed_version_ids
            })
            .unwrap_or_default();

        let after_removal: Vec<String> = before_removal
            .iter()
            .filter(|&v| !versions_to_remove.contains(v))
            .cloned()
            .collect();

        if before_removal.len() == after_removal.len() {
            return after_removal;
        }

        // Get all subnet records
        let subnets_key = make_subnet_list_record_key();
        let subnets = self
            .get(subnets_key.as_bytes(), version)
            .map(|reg_value| {
                SubnetListRecord::decode(reg_value.value.as_slice())
                    .unwrap()
                    .subnets
            })
            .unwrap_or_default();

        // Try to find a replica version that is both, part of the payload and used by a subnet
        let in_use = subnets
            .iter()
            .map(|id| {
                let subnet_id = SubnetId::new(PrincipalId::try_from(id).unwrap());
                let subnet_key = make_subnet_record_key(subnet_id);
                let reg_value = self.get(subnet_key.as_bytes(), version).unwrap();
                SubnetRecord::decode(reg_value.value.as_slice())
                    .unwrap()
                    .replica_version_id
            })
            .filter(|id| versions_to_remove.contains(id))
            .collect::<BTreeSet<String>>();

        if !in_use.is_empty() {
            panic!(
                "{LOG_PREFIX}Cannot retire versions {in_use:?}, because they are currently deployed to a subnet!"
            );
        }

        // Do the same for unassigned node record
        let unassigned_key = make_unassigned_nodes_config_record_key();
        let in_use = self
            .get(unassigned_key.as_bytes(), version)
            .map(|reg_value| {
                UnassignedNodesConfigRecord::decode(reg_value.value.as_slice())
                    .unwrap()
                    .replica_version
            })
            .filter(|id| versions_to_remove.contains(id));

        if let Some(version) = in_use {
            panic!(
                "{LOG_PREFIX}Cannot retire version {version}, because it is currently deployed to unassigned nodes!"
            );
        }

        println!(
            "{LOG_PREFIX}Blessed versions before: {before_removal:?} and after: {after_removal:?}"
        );

        after_removal
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
        if self
            .guest_launch_measurements
            .as_ref()
            .is_some_and(|measurements| measurements.guest_launch_measurements.is_empty())
        {
            return Err("guest_launch_measurements must not be an empty vector".into());
        }

        if self.is_electing_a_version()? || self.is_unelecting_a_version() {
            Ok(())
        } else {
            Err("At least one version has to be elected or unelected.".into())
        }
    }
}
