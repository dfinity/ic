use crate::{
    common::LOG_PREFIX,
    mutations::do_update_elected_replica_versions::UpdateElectedReplicaVersionsPayload,
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

impl Registry {
    /// Removes replica versions from the registry and retires them, i.e., removes
    /// the versions' IDs from the list of blessed replica versions.
    /// This function will fail if the payload contains a replica version that isn't
    /// part of the currently blessed replica versions, or if the payload is empty.
    /// It will also fail if the payload contains a version that is currently used
    /// by a subnet or unassigned node.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for retiring replica versions has been accepted.
    /// TODO(CON-924): Remove this function once release team switches to new "update
    /// elected replica versions" proposal, and it is supported by frontends.
    pub fn do_retire_replica_version(&mut self, payload: RetireReplicaVersionPayload) {
        println!("{}do_retire_replica_version: {:?}", LOG_PREFIX, payload);
        assert!(
            !payload.replica_version_ids.is_empty(),
            "{}RetireReplicaVersionPayload cannot be empty.",
            LOG_PREFIX
        );

        self.do_update_elected_replica_versions(UpdateElectedReplicaVersionsPayload {
            replica_version_to_elect: None,
            release_package_sha256_hex: None,
            release_package_urls: vec![],
            guest_launch_measurement_sha256_hex: None,
            replica_versions_to_unelect: payload.replica_version_ids,
        });
    }
}

/// The payload of a proposal to retire a set of replica versions.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from an
/// RetireReplicaVersionPayload, it is possible to construct a ReplicaVersionRecord.
///
/// See /rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RetireReplicaVersionPayload {
    /// Version IDs. These can be anything, they have no semantics.
    pub replica_version_ids: Vec<String>,
}
