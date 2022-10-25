use std::{collections::BTreeSet, convert::TryFrom, iter::FromIterator};

use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{PrincipalId, SubnetId};
use serde::Serialize;

use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions,
    subnet::v1::{SubnetListRecord, SubnetRecord},
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_blessed_replica_version_key, make_replica_version_key, make_subnet_list_record_key,
    make_subnet_record_key, make_unassigned_nodes_config_record_key,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

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
    pub fn do_retire_replica_version(&mut self, payload: RetireReplicaVersionPayload) {
        println!("{}do_retire_replica_version: {:?}", LOG_PREFIX, payload);
        assert!(
            !payload.replica_version_ids.is_empty(),
            "{}RetireReplicaVersionPayload cannot be empty.",
            LOG_PREFIX
        );

        let version = self.latest_version();
        // Get the current list
        let blessed_key = make_blessed_replica_version_key();
        let before_removal = self
            .get(blessed_key.as_bytes(), version)
            .map(|reg_value| {
                decode_registry_value::<BlessedReplicaVersions>(reg_value.value.clone())
                    .blessed_version_ids
            })
            .unwrap_or_default();

        let set = BTreeSet::from_iter(payload.replica_version_ids);

        // Get all subnet records
        let subnets_key = make_subnet_list_record_key();
        let subnets = self
            .get(subnets_key.as_bytes(), version)
            .map(|reg_value| {
                decode_registry_value::<SubnetListRecord>(reg_value.value.clone()).subnets
            })
            .unwrap_or_default();

        // Try to find a replica version that is both, part of the payload and used by a subnet
        let in_use = subnets
            .iter()
            .map(|id| {
                let subnet_id = SubnetId::new(PrincipalId::try_from(id).unwrap());
                let subnet_key = make_subnet_record_key(subnet_id);
                let reg_value = self.get(subnet_key.as_bytes(), version).unwrap();
                decode_registry_value::<SubnetRecord>(reg_value.value.clone()).replica_version_id
            })
            .filter(|id| set.contains(id))
            .collect::<BTreeSet<String>>();

        if !in_use.is_empty() {
            panic!(
                "{}Cannot retire versions {:?}, because they are currently deployed to a subnet!",
                LOG_PREFIX, in_use
            );
        }

        // Do the same for unassigned node record
        let unassigned_key = make_unassigned_nodes_config_record_key();
        let in_use = self
            .get(unassigned_key.as_bytes(), version)
            .map(|reg_value| {
                decode_registry_value::<UnassignedNodesConfigRecord>(reg_value.value.clone())
                    .replica_version
            })
            .filter(|id| set.contains(id));

        if let Some(version) = in_use {
            panic!(
                "{}Cannot retire version {}, because it is currently deployed to unassigned nodes!",
                LOG_PREFIX, version
            );
        }

        let after_removal = before_removal
            .iter()
            .filter(|&v| !set.contains(v))
            .cloned()
            .collect();

        println!(
            "{}Blessed versions before: {:?} and after: {:?}",
            LOG_PREFIX, before_removal, after_removal
        );

        let mut mutations: Vec<RegistryMutation> = set
            .iter()
            .map(|v| RegistryMutation {
                mutation_type: registry_mutation::Type::Delete as i32,
                key: make_replica_version_key(v).as_bytes().to_vec(),
                value: vec![],
            })
            .collect();

        mutations.push(RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: blessed_key.as_bytes().to_vec(),
            value: encode_or_panic(&BlessedReplicaVersions {
                blessed_version_ids: after_removal,
            }),
        });

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
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
