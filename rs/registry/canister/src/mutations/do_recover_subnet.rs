//! Contains methods to recover a stalled subnet
//!
//! A subnet is recovered by updating the subnet's `CatchUpPackageContents`
//! (which triggers each Replica in the subnet to upgrade themselves out of a
//! bad state) and optionally replacing any (potentially) broken nodes in the
//! subnet with a set of known-good nodes

use crate::{
    common::LOG_PREFIX,
    mutations::{
        common::{decode_registry_value, encode_or_panic},
        dkg::{SetupInitialDKGArgs, SetupInitialDKGResponse},
    },
    registry::Registry,
};

use candid::{CandidType, Deserialize, Encode};
use dfn_core::api::{call, CanisterId};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_protobuf::registry::subnet::v1::RegistryStoreUri;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use std::convert::TryFrom;

use on_wire::bytes;

impl Registry {
    /// Recover a subnet
    pub async fn do_recover_subnet(&mut self, payload: RecoverSubnetPayload) {
        println!("{}do_recover_subnet: {:?}", LOG_PREFIX, payload);

        let subnet_id = SubnetId::from(payload.subnet_id);
        let cup_contents_key = make_catch_up_package_contents_key(subnet_id).into_bytes();
        let RegistryValue {
            value: cup_contents_vec,
            version: cup_version,
            deletion_marker: _,
        } = self.get(&cup_contents_key, self.latest_version()).unwrap();
        let mut cup_contents =
            decode_registry_value::<CatchUpPackageContents>(cup_contents_vec.clone());

        let mut mutations: Vec<RegistryMutation> = vec![];

        // If we have a registry_store_uri in the payload, that means that this
        // is a special "become nns" catch up package, and we should not run a
        // dkg. In all other cases we run a new dkg for the subnet.
        if let Some(registry_store_uri_info) = payload.registry_store_uri {
            cup_contents.registry_store_uri = Some(RegistryStoreUri {
                uri: registry_store_uri_info.0,
                hash: registry_store_uri_info.1,
                registry_version: registry_store_uri_info.2,
            })
        } else {
            cup_contents.registry_store_uri = None;

            let dkg_nodes = if let Some(replacement_nodes) = payload.replacement_nodes.clone() {
                let replace_nodes_mutations = self
                    .make_replace_subnet_membership_mutation(subnet_id, replacement_nodes.clone());

                mutations.push(replace_nodes_mutations);
                replacement_nodes
            } else {
                let subnet_record = self.get_subnet_or_panic(subnet_id);
                subnet_record
                    .membership
                    .iter()
                    .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
                    .collect()
            };

            let registry_version = self.latest_version();

            let request = SetupInitialDKGArgs {
                node_ids: dkg_nodes.iter().map(|n| n.get()).collect(),
                registry_version,
            };

            let response_bytes = call(
                CanisterId::ic_00(),
                "setup_initial_dkg",
                bytes,
                Encode!(&request).unwrap(),
            )
            .await
            .unwrap();

            let RegistryValue {
                value: _,
                version: new_cup_version,
                deletion_marker: _,
            } = self.get(&cup_contents_key, self.latest_version()).unwrap();

            if cup_version != new_cup_version {
                panic!(
                    "CUP for Subnet {} was updated during the `setup_initial_dkg` call",
                    subnet_id
                );
            }

            let dkg_response = SetupInitialDKGResponse::decode(&response_bytes).unwrap();

            let new_subnet_threshold_signing_pubkey_mutation = RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_crypto_threshold_signing_pubkey_key(subnet_id)
                    .as_bytes()
                    .to_vec(),
                value: encode_or_panic(&dkg_response.subnet_threshold_public_key),
            };

            mutations.push(new_subnet_threshold_signing_pubkey_mutation);

            cup_contents.initial_ni_dkg_transcript_low_threshold =
                Some(dkg_response.low_threshold_transcript_record);
            cup_contents.initial_ni_dkg_transcript_high_threshold =
                Some(dkg_response.high_threshold_transcript_record);
        }

        // Set the height, time and state hash of the payload
        cup_contents.height = payload.height;
        cup_contents.time = payload.time_ns;
        cup_contents.state_hash = payload.state_hash;

        mutations.push(RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: cup_contents_key.clone(),
            value: encode_or_panic(&cup_contents),
        });

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// A payload used to recover a subnet that has stalled
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoverSubnetPayload {
    /// The subnet ID to add the recovery CUP to
    pub subnet_id: PrincipalId,
    /// The height of the CUP
    pub height: u64,
    /// The block time to start from (nanoseconds from Epoch)
    pub time_ns: u64,
    /// The hash of the state
    pub state_hash: Vec<u8>,
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<NodeId>>,
    /// A uri from which data to replace the registry local store should be
    /// downloaded
    pub registry_store_uri: Option<(String, String, u64)>,
}
