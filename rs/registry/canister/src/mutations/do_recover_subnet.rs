//! Contains methods to recover a stalled subnet
//!
//! A subnet is recovered by updating the subnet's `CatchUpPackageContents`
//! (which triggers each Replica in the subnet to upgrade themselves out of a
//! bad state) and optionally replacing any (potentially) broken nodes in the
//! subnet with a set of known-good nodes

use crate::mutations::do_create_subnet::EcdsaInitialConfig;
use crate::registry::Version;
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
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::registry::subnet::v1::RegistryStoreUri;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_record_key,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use ic_registry_transport::upsert;
use on_wire::bytes;
use serde::Serialize;
use std::convert::TryFrom;

impl Registry {
    /// Recover a subnet
    pub async fn do_recover_subnet(&mut self, payload: RecoverSubnetPayload) {
        println!("{}do_recover_subnet: {:?}", LOG_PREFIX, payload);

        self.validate_ecdsa_recover_subnet_payload(&payload);

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

            let subnet_record = self.get_subnet_or_panic(subnet_id);

            let dkg_nodes = if let Some(replacement_nodes) = payload.replacement_nodes.clone() {
                let replace_nodes_mutations = self
                    .make_replace_subnet_membership_mutation(subnet_id, replacement_nodes.clone());

                mutations.push(replace_nodes_mutations);
                replacement_nodes
            } else {
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

            let ecdsa_initializations = self
                .get_all_initial_ecdsa_dealings_from_ic00(
                    &payload.ecdsa_config,
                    dkg_nodes.iter().map(|n| n.get()).collect(),
                )
                .await;

            // If ECDSA config is set, we must both update the subnets ecdsa_config
            // and make sure the subnet is not listed as signing_subnet for keys it no longer holds
            if let Some(ref new_ecdsa_config) = payload.ecdsa_config {
                // get current set of keys

                let new_key_list: Vec<EcdsaKeyId> = new_ecdsa_config
                    .keys
                    .iter()
                    .map(|key_request| key_request.key_id.clone())
                    .collect();

                mutations.append(&mut self.mutations_to_disable_subnet_signing(
                    subnet_id,
                    &self.get_keys_that_will_be_removed_from_subnet(subnet_id, new_key_list),
                ));
                // Update ECDSA configuration on subnet record to reflect new holdings
                let mut subnet_record = self.get_subnet_or_panic(subnet_id);
                subnet_record.ecdsa_config = Some(new_ecdsa_config.clone().into());
                mutations.push(upsert(
                    &make_subnet_record_key(subnet_id),
                    encode_or_panic(&subnet_record),
                ));
            }

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
            cup_contents.ecdsa_initializations = ecdsa_initializations;
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

    /// Validates that the requested key exists outside of the subnet being recovered and that if
    /// requested from a particular subnet, is actually held there. This is similar to
    /// validation in do_create_subnet except for constraints to avoid requesting keys from itself.
    fn validate_ecdsa_recover_subnet_payload(&self, payload: &RecoverSubnetPayload) {
        if payload.ecdsa_config.is_none() {
            return;
        }

        let ecdsa_config = payload.ecdsa_config.as_ref().unwrap();

        let ecdsa_subnet_map = self.get_ecdsa_keys_to_subnets_map();

        for key_request in &ecdsa_config.keys {
            // Requested key must be a known key.
            if !ecdsa_subnet_map.contains_key(&key_request.key_id) {
                panic!(
                        "{}Cannot recover subnet '{}': The requested ECDSA key '{}' was not found in any subnet.",
                        LOG_PREFIX, payload.subnet_id, key_request.key_id
                    );
            }

            let subnets_for_key = ecdsa_subnet_map.get(&key_request.key_id).unwrap();
            // If targeting subnet_id, validate it is found there and is not the same as this subnet
            if let Some(ref subnet_id_principal) = key_request.subnet_id {
                if subnet_id_principal == &payload.subnet_id {
                    panic!(
                            "{}Cannot recover subnet '{}': Attempted to recover ECDSA key '{}' by \
                               requesting it from itself.  Subnets cannot recover ECDSA keys from themselves.",
                            LOG_PREFIX, payload.subnet_id, key_request.key_id
                        );
                }

                let subnet_id = SubnetId::new(*subnet_id_principal);
                if !subnets_for_key.contains(&subnet_id) {
                    panic!(
                        "{}Cannot recover subnet '{}': The requested ECDSA key '{}' \
                           is not available in targeted subnet '{}'.",
                        LOG_PREFIX, payload.subnet_id, key_request.key_id, subnet_id_principal
                    );
                }
            } else if subnets_for_key.contains(&SubnetId::new(payload.subnet_id))
                && subnets_for_key.len() == 1
            {
                panic!(
                        "{}Cannot recover subnet '{}': The requested ECDSA key '{}' is only available in \
                           the subnet being recovered.  Subnets cannot recover ECDSA keys from themselves.",
                        LOG_PREFIX, payload.subnet_id, key_request.key_id
                    );
            }
        }
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
    /// ECDSA configuration must be specified if keys will be recovered to this subnet
    /// Any keys that this subnet could sign for will immediately be available to sign with
    /// Any new keys will not
    /// Any keys that were signing keys that are not included here will be removed from the list
    pub ecdsa_config: Option<EcdsaInitialConfig>,
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
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use crate::mutations::do_create_subnet::EcdsaInitialConfig;
    use crate::mutations::do_create_subnet::EcdsaKeyRequest;
    use crate::mutations::do_recover_subnet::{
        panic_if_record_changed_across_versions, RecoverSubnetPayload,
    };
    use crate::registry::Registry;
    use ic_base_types::SubnetId;
    use ic_ic00_types::{EcdsaCurve, EcdsaKeyId};
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
    use ic_registry_transport::{delete, upsert};
    use ic_test_utilities::types::ids::subnet_test_id;

    fn get_default_recover_subnet_payload(subnet_id: SubnetId) -> RecoverSubnetPayload {
        RecoverSubnetPayload {
            subnet_id: subnet_id.get(),
            height: 0,
            time_ns: 0,
            state_hash: vec![],
            replacement_nodes: None,
            registry_store_uri: None,
            ecdsa_config: None,
        }
    }

    fn setup_registry_with_subnet_holding_key(key_id: &EcdsaKeyId) -> (Registry, SubnetId) {
        let subnet_id_holding_key = subnet_test_id(1001);
        let mut registry = invariant_compliant_registry();

        // add a node for our existing subnet that has the ECDSA key
        let (mutate_request, node_ids) = prepare_registry_with_nodes(1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let mut subnet_record: SubnetRecord = get_invariant_compliant_subnet_record(node_ids);
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }
            .into(),
        );

        let fake_subnet_mutation = add_fake_subnet(
            subnet_id_holding_key,
            &mut subnet_list_record,
            subnet_record,
        );
        registry.maybe_apply_mutation_internal(fake_subnet_mutation);
        (registry, subnet_id_holding_key)
    }

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
    #[should_panic(expected = "[Registry] Record for some_key not found in registry")]
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

    // Note: this can only be unit-tested b/c it fails before we hit inter-canister calls
    // for DKG + ECDSA
    #[test]
    #[should_panic(
        expected = "Cannot recover subnet 'ge6io-epiam-aaaaa-aaaap-yai': The requested ECDSA key \
        'Secp256k1:test_key_id' was not found in any subnet."
    )]
    fn do_recover_subnet_should_panic_if_ecdsa_keys_non_existing() {
        let mut registry = invariant_compliant_registry();
        let subnet_id = subnet_test_id(1000);
        let mut payload = get_default_recover_subnet_payload(subnet_id);

        payload.ecdsa_config = Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 1,
            keys: vec![EcdsaKeyRequest {
                key_id: EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test_key_id".to_string(),
                },
                subnet_id: None,
            }],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "Cannot recover subnet 'ge6io-epiam-aaaaa-aaaap-yai': The requested ECDSA key \
        'Secp256k1:test_key_id' is not available in targeted subnet '3ifty-exlam-aaaaa-aaaap-yai'."
    )]
    fn do_recover_subnet_should_panic_if_ecdsa_keys_non_existing_from_requested_subnet() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        let subnet_id_to_recover = subnet_test_id(1000);
        let subnet_id_to_request_key_from = subnet_test_id(1003);
        let (mut registry, subnet_id_holding_key) = setup_registry_with_subnet_holding_key(&key_id);

        assert_ne!(subnet_id_holding_key, subnet_id_to_request_key_from);

        // Make a request for the key from a subnet that does not have the key
        let mut payload = get_default_recover_subnet_payload(subnet_id_to_recover);
        payload.ecdsa_config = Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 1,
            keys: vec![EcdsaKeyRequest {
                key_id,
                subnet_id: Some(subnet_id_to_request_key_from.get()),
            }],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "Cannot recover subnet '337oy-l7jam-aaaaa-aaaap-yai': Attempted to recover \
        ECDSA key 'Secp256k1:test_key_id' by requesting it from itself.  \
        Subnets cannot recover ECDSA keys from themselves."
    )]
    fn do_recover_subnet_should_panic_if_attempting_to_get_ecdsa_keys_from_itself() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };

        let (mut registry, subnet_id) = setup_registry_with_subnet_holding_key(&key_id);

        // We attempt to get the key from the subnet requesting it
        let mut payload = get_default_recover_subnet_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 1,
            keys: vec![EcdsaKeyRequest {
                key_id,
                subnet_id: Some(subnet_id.get()),
            }],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "Cannot recover subnet '337oy-l7jam-aaaaa-aaaap-yai': The requested ECDSA key \
        'Secp256k1:test_key_id' is only available in the subnet being recovered.  \
         Subnets cannot recover ECDSA keys from themselves."
    )]
    fn do_recover_subnet_panics_if_no_other_subnet_holds_a_requested_key() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        // We use the subnet_id from our setup, which is the only subnet holding the key
        let (mut registry, subnet_id) = setup_registry_with_subnet_holding_key(&key_id);

        // We attempt to get the key even though the only subnet holding it is the one we're recovering
        let mut payload = get_default_recover_subnet_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 1,
            keys: vec![EcdsaKeyRequest {
                key_id,
                subnet_id: None,
            }],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }
}
