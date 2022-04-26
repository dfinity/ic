//! Contains methods to recover a stalled subnet
//!
//! A subnet is recovered by updating the subnet's `CatchUpPackageContents`
//! (which triggers each Replica in the subnet to upgrade themselves out of a
//! bad state) and optionally replacing any (potentially) broken nodes in the
//! subnet with a set of known-good nodes

use crate::{
    common::LOG_PREFIX,
    mutations::{
        common::encode_or_panic,
        dkg::{SetupInitialDKGArgs, SetupInitialDKGResponse},
    },
    registry::Registry,
};

use candid::{CandidType, Deserialize, Encode};
use dfn_core::api::{call, CanisterId};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::RegistryStoreUri;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_record_key,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use serde::Serialize;
use std::convert::TryFrom;

use crate::registry::Version;
use on_wire::bytes;

impl Registry {
    /// Recover a subnet
    pub async fn do_recover_subnet(&mut self, payload: RecoverSubnetPayload) {
        println!("{}do_recover_subnet: {:?}", LOG_PREFIX, payload);

        let pre_call_registry_version = self.latest_version();

        let subnet_id = SubnetId::from(payload.subnet_id);

        // Get our base CUP, which is modified to recover the subnet
        let mut cup_contents = self
            .get_subnet_catch_up_package(subnet_id, Some(pre_call_registry_version))
            .unwrap();

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

            let request = SetupInitialDKGArgs {
                node_ids: dkg_nodes.iter().map(|n| n.get()).collect(),
                registry_version: pre_call_registry_version,
            };

            let response_bytes = call(
                CanisterId::ic_00(),
                "setup_initial_dkg",
                bytes,
                Encode!(&request).unwrap(),
            )
            .await
            .unwrap();

            let post_call_registry_version = self.latest_version();

            // Check to make sure records did not change during the async call
            panic_if_record_changed_across_versions(
                self,
                &make_subnet_record_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "Subnet with ID {} was updated during the `setup_initial_dkg` call",
                    subnet_id
                ),
            );

            panic_if_record_changed_across_versions(
                self,
                &make_crypto_threshold_signing_pubkey_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "Threshold Signing Pubkey for Subnet {} was updated during the `setup_initial_dkg` call",
                    subnet_id
                ),
            );

            panic_if_record_changed_across_versions(
                self,
                &make_catch_up_package_contents_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "CUP for Subnet {} was updated during the `setup_initial_dkg` call",
                    subnet_id
                ),
            );

            let dkg_response = SetupInitialDKGResponse::decode(&response_bytes).unwrap();

            let new_subnet_threshold_signing_pubkey_mutation = RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_crypto_threshold_signing_pubkey_key(subnet_id).into_bytes(),
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
            key: make_catch_up_package_contents_key(subnet_id).into_bytes(),
            value: encode_or_panic(&cup_contents),
        });

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// A payload used to recover a subnet that has stalled
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

fn panic_if_record_changed_across_versions(
    registry: &Registry,
    key: &str,
    initial_registry_version: Version,
    final_registry_version: Version,
    panic_message: String,
) {
    let initial_record_version =
        get_record_version_as_of_registry_version(registry, key, initial_registry_version);
    let final_record_version =
        get_record_version_as_of_registry_version(registry, key, final_registry_version);

    if initial_record_version != final_record_version {
        panic!("{}", panic_message);
    }
}

fn get_record_version_as_of_registry_version(
    registry: &Registry,
    record_key: &str,
    version: Version,
) -> Version {
    registry
        .get(record_key.as_bytes(), version)
        .map(|record| record.version)
        .unwrap_or_else(|| {
            panic!(
                "{}Record for {} not found in registry",
                LOG_PREFIX, record_key
            );
        })
}

#[cfg(test)]
mod test {
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_recover_subnet::panic_if_record_changed_across_versions;
    use ic_registry_transport::{delete, upsert};

    #[test]
    fn panic_if_value_changed_across_versions_no_change() {
        let mut registry = invariant_compliant_registry();
        let mutation = upsert("foo", "Bar");
        registry.maybe_apply_mutation_internal(vec![mutation]);

        panic_if_record_changed_across_versions(
            &registry,
            "foo",
            2_u64,
            5_u64,
            "panic message".to_string(),
        );
    }

    #[test]
    fn panic_if_value_changed_across_versions_unrelated_change() {
        let mut registry = invariant_compliant_registry();
        let mutation = upsert("foo", "Bar");
        registry.maybe_apply_mutation_internal(vec![mutation]);
        let initial_version = registry.latest_version();
        registry.maybe_apply_mutation_internal(vec![upsert("bar", "baz")]);
        let final_version = registry.latest_version();

        assert!(initial_version != final_version);

        // should not panic
        panic_if_record_changed_across_versions(
            &registry,
            "foo",
            initial_version,
            final_version,
            "panic message".to_string(),
        );
    }

    #[test]
    #[should_panic(expected = "A custom panic message")]
    fn panic_if_value_changed_across_versions_yes_change() {
        let mut registry = invariant_compliant_registry();
        let mutation = upsert("foo", "Bar");
        registry.maybe_apply_mutation_internal(vec![mutation]);
        let initial_version = registry.latest_version();
        // value doesn't need to change for this to work
        registry.maybe_apply_mutation_internal(vec![upsert("foo", "Bar")]);
        let final_version = registry.latest_version();

        assert!(initial_version != final_version);

        // should panic
        panic_if_record_changed_across_versions(
            &registry,
            "foo",
            initial_version,
            final_version,
            "A custom panic message".to_string(),
        );
    }
    #[test]
    #[should_panic(expected = "[Registry Canister] Record for some_key not found in registry")]
    fn panic_if_value_changed_across_versions_record_not_found() {
        let mut registry = invariant_compliant_registry();
        let mutation = upsert("foo", "Bar");
        registry.maybe_apply_mutation_internal(vec![mutation]);
        let initial_version = registry.latest_version();
        registry.maybe_apply_mutation_internal(vec![delete("foo")]);
        let final_version = registry.latest_version();

        assert!(initial_version != final_version);

        panic_if_record_changed_across_versions(
            &registry,
            "some_key",
            initial_version,
            final_version,
            "panic message".to_string(),
        );
    }
}
