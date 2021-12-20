use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_protobuf::registry::replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord};
use ic_registry_keys::{make_blessed_replica_version_key, make_replica_version_key};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

impl Registry {
    /// Adds a new replica version to the registry and blesses it, i.e., adds
    /// the version's ID to the list of blessed replica versions.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for blessing a new replica version has been accepted.
    pub fn do_bless_replica_version(&mut self, payload: BlessReplicaVersionPayload) {
        println!("{}do_bless_replica_version: {:?}", LOG_PREFIX, payload);

        let version = self.latest_version();
        // Get the current list
        let blessed_key = make_blessed_replica_version_key();
        let before_append = match self.get(blessed_key.as_bytes(), version) {
            Some(old_blessed_replica_version) => {
                decode_registry_value::<BlessedReplicaVersions>(
                    old_blessed_replica_version.value.clone(),
                )
                .blessed_version_ids
            }
            None => vec![],
        };

        let after_append = {
            let mut copy = before_append.clone();
            copy.push(payload.replica_version_id.clone());
            copy
        };
        println!(
            "{}Blessed version before: {:?} and after: {:?}",
            LOG_PREFIX, before_append, after_append
        );

        let mutations = vec![
            // Register the new version (that is, insert the new ReplicaVersionRecord)
            RegistryMutation {
                mutation_type: registry_mutation::Type::Insert as i32,
                key: make_replica_version_key(&payload.replica_version_id)
                    .as_bytes()
                    .to_vec(),
                value: encode_or_panic(&ReplicaVersionRecord {
                    release_package_url: payload.release_package_url.clone(),
                    release_package_sha256_hex: payload.release_package_sha256_hex,
                }),
            },
            // Bless the new version (that is, update the list of blessed versions)
            RegistryMutation {
                mutation_type: registry_mutation::Type::Upsert as i32,
                key: blessed_key.as_bytes().to_vec(),
                value: encode_or_panic(&BlessedReplicaVersions {
                    blessed_version_ids: after_append,
                }),
            },
        ];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to bless a given replica version.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from a
/// BlessingProposalPayload, it is possible to construct a ReplicaVersionRecord
/// from a BlessingProposalPayload.
///
/// See /rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlessReplicaVersionPayload {
    /// Version ID. This can be anything, it has not semantics. The reason it is
    /// part of the payload is that it will be needed in the subsequent step
    /// of upgrading individual subnets.
    pub replica_version_id: String,

    /// The URL against which a HTTP GET request will return a release package
    /// that corresponds to this version
    pub release_package_url: String,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_url'
    pub release_package_sha256_hex: String,
}
