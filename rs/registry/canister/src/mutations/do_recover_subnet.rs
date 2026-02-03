//! Contains methods to recover a stalled subnet
//!
//! A subnet is recovered by updating the subnet's `CatchUpPackageContents`
//! (which triggers each Replica in the subnet to upgrade themselves out of a
//! bad state) and optionally replacing any (potentially) broken nodes in the
//! subnet with a set of known-good nodes

use crate::chain_key::{InitialChainKeyConfigInternal, KeyConfigRequestInternal};
use crate::{
    common::LOG_PREFIX,
    registry::{Registry, Version},
};
use candid::{CandidType, Deserialize, Encode};
use dfn_core::api::{CanisterId, call};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_management_canister_types_private::{
    MasterPublicKeyId, SetupInitialDKGArgs, SetupInitialDKGResponse,
};
use ic_protobuf::registry::subnet::v1::{ChainKeyConfig as ChainKeyConfigPb, RegistryStoreUri};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_record_key,
};
use ic_registry_subnet_features::KeyConfig as KeyConfigInternal;
use ic_registry_transport::{
    pb::v1::{RegistryMutation, registry_mutation},
    upsert,
};
use on_wire::bytes;
use prost::Message;
use serde::Serialize;
use std::convert::TryFrom;

impl Registry {
    /// Recover a subnet
    pub async fn do_recover_subnet(&mut self, payload: RecoverSubnetPayload) {
        println!("{LOG_PREFIX}do_recover_subnet: {payload:?}");

        self.validate_recover_subnet_payload(&payload);

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

            let mut subnet_record = self.get_subnet_or_panic(subnet_id);

            // If [SubnetRecord::halt_at_cup_height] is set to `true`, then the Subnet was
            // instructed to halt after reaching the next CUP height. Since the Consensus is
            // looking at the registry version from the highest CUP when considering this flag,
            // we reset it to `false` but flip the `is_halted` flag to `true`, so the subnet
            // remains halted but can be later unhalted by sending an appropriate proposal which
            // resets `is_halted` to `false`.
            if subnet_record.halt_at_cup_height {
                subnet_record.halt_at_cup_height = false;
                subnet_record.is_halted = true;
            }

            let dkg_nodes = if let Some(replacement_nodes) = payload.replacement_nodes.clone() {
                self.replace_subnet_record_membership(
                    subnet_id,
                    &mut subnet_record,
                    replacement_nodes.clone(),
                );

                replacement_nodes
            } else {
                subnet_record
                    .membership
                    .iter()
                    .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
                    .collect()
            };

            let request = SetupInitialDKGArgs::new(
                dkg_nodes.clone(),
                RegistryVersion::new(pre_call_registry_version),
            );

            let initial_chain_key_config =
                payload
                    .chain_key_config
                    .clone()
                    .map(|initial_chain_key_config| {
                        InitialChainKeyConfigInternal::try_from(initial_chain_key_config)
                            .expect("Invalid InitialChainKeyConfig")
                    });

            // Call setup_initial_dkg and reshare_chain_key in parallel.
            // Since both calls may take up to 2 DKG intervals to complete, this speeds up generation of a recovery cup.
            let (response_bytes, chain_key_initializations) = futures::join!(
                call(
                    CanisterId::ic_00(),
                    "setup_initial_dkg",
                    bytes,
                    Encode!(&request).unwrap(),
                ),
                self.get_all_chain_key_reshares_from_ic00(&initial_chain_key_config, dkg_nodes)
            );
            let response_bytes = response_bytes.unwrap();

            if let Some(initial_chain_key_config) = initial_chain_key_config {
                // If chain key config is set, we must both update the subnet's chain_key_config
                // and make sure the subnet is not listed as chain-key-enabled subnet for keys it no longer
                // holds.
                let chain_key_disable = {
                    let new_keys = initial_chain_key_config.key_ids();
                    self.get_keys_that_will_be_removed_from_subnet(subnet_id, new_keys)
                };
                mutations.append(
                    &mut self.mutations_to_disable_subnet_chain_key(subnet_id, &chain_key_disable),
                );

                // Update chain key configuration on subnet record to reflect new holdings.
                subnet_record.chain_key_config = {
                    let chain_key_config_pb = ChainKeyConfigPb::from(initial_chain_key_config);
                    Some(chain_key_config_pb)
                };
            }

            // Push all of our subnet_record mutations
            mutations.push(upsert(
                make_subnet_record_key(subnet_id),
                subnet_record.encode_to_vec(),
            ));

            let post_call_registry_version = self.latest_version();

            // Check to make sure records did not change during the async call
            panic_if_record_changed_across_versions(
                self,
                &make_subnet_record_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "Subnet with ID {subnet_id} was updated during the `setup_initial_dkg` call"
                ),
            );

            panic_if_record_changed_across_versions(
                self,
                &make_crypto_threshold_signing_pubkey_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "Threshold Signing Pubkey for Subnet {subnet_id} was updated during the `setup_initial_dkg` call"
                ),
            );

            panic_if_record_changed_across_versions(
                self,
                &make_catch_up_package_contents_key(subnet_id),
                pre_call_registry_version,
                post_call_registry_version,
                format!(
                    "CUP for Subnet {subnet_id} was updated during the `setup_initial_dkg` call"
                ),
            );

            let dkg_response = SetupInitialDKGResponse::decode(&response_bytes).unwrap();

            let new_subnet_threshold_signing_pubkey_mutation = RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_crypto_threshold_signing_pubkey_key(subnet_id).into_bytes(),
                value: dkg_response.subnet_threshold_public_key.encode_to_vec(),
            };

            mutations.push(new_subnet_threshold_signing_pubkey_mutation);

            cup_contents.initial_ni_dkg_transcript_low_threshold =
                Some(dkg_response.low_threshold_transcript_record);
            cup_contents.initial_ni_dkg_transcript_high_threshold =
                Some(dkg_response.high_threshold_transcript_record);

            cup_contents.chain_key_initializations = chain_key_initializations;

            // Unset this obsolete field for consistency (replaced by `chain_key_initializations`).
            cup_contents.ecdsa_initializations = vec![];
        }

        // Set the height, time and state hash of the payload
        cup_contents.height = payload.height;
        cup_contents.time = payload.time_ns;
        cup_contents.state_hash = payload.state_hash;

        mutations.push(RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: make_catch_up_package_contents_key(subnet_id).into_bytes(),
            value: cup_contents.encode_to_vec(),
        });

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations)
    }

    /// Ensures the requested Chain keys exist somewhere.
    /// Ensures that a subnet_id is specified for ChainKeyRequests.
    /// Ensures that the requested key exists outside of the subnet being recovered.
    /// Ensures that the requested key exists on the specified subnet.
    /// This is similar to validation in do_create_subnet except for constraints to avoid requesting
    /// keys from the subnet.
    fn validate_recover_subnet_payload(&self, payload: &RecoverSubnetPayload) {
        let Some(initial_chain_key_config) = &payload.chain_key_config else {
            return; // Nothing to do.
        };

        let initial_chain_key_config =
            InitialChainKeyConfigInternal::try_from(initial_chain_key_config.clone())
                .unwrap_or_else(|err| {
                    panic!("{LOG_PREFIX}Invalid RecoverSubnetPayload.chain_key_config: {err}");
                });

        let own_subnet_id = Some(payload.subnet_id);
        self.validate_initial_chain_key_config(&initial_chain_key_config, own_subnet_id)
            .unwrap_or_else(|err| {
                panic!(
                    "{}Cannot recover subnet '{}': {}",
                    LOG_PREFIX, payload.subnet_id, err
                );
            });
    }
}

/// A payload used to recover a subnet that has stalled
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
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

    /// Chain key configuration must be specified if keys will be recovered to this subnet.
    /// Any keys that this subnet could sign for will immediately be available to sign with.
    /// Any new keys will not.
    /// Any keys that were signing keys that are not included here will be removed from the list.
    pub chain_key_config: Option<InitialChainKeyConfig>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct InitialChainKeyConfig {
    pub key_configs: Vec<KeyConfigRequest>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
    pub max_parallel_pre_signature_transcripts_in_creation: Option<u32>,
}

impl From<InitialChainKeyConfigInternal> for InitialChainKeyConfig {
    fn from(src: InitialChainKeyConfigInternal) -> Self {
        let InitialChainKeyConfigInternal {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        } = src;

        let key_configs = key_configs
            .into_iter()
            .map(KeyConfigRequest::from)
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        }
    }
}

impl TryFrom<InitialChainKeyConfig> for InitialChainKeyConfigInternal {
    type Error = String;

    fn try_from(src: InitialChainKeyConfig) -> Result<Self, Self::Error> {
        let InitialChainKeyConfig {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        } = src;

        let mut key_config_validation_errors = vec![];
        let key_configs = key_configs
            .into_iter()
            .filter_map(|key_config_request| {
                KeyConfigRequestInternal::try_from(key_config_request)
                    .map_err(|err| {
                        key_config_validation_errors.push(err);
                    })
                    .ok()
            })
            .collect::<Vec<_>>();

        if !key_config_validation_errors.is_empty() {
            let key_config_validation_errors = key_config_validation_errors.join(", ");
            return Err(format!(
                "Invalid InitialChainKeyConfig.key_configs: {key_config_validation_errors}"
            ));
        }

        Ok(Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct KeyConfigRequest {
    pub key_config: Option<KeyConfig>,
    pub subnet_id: Option<PrincipalId>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct KeyConfig {
    pub key_id: Option<MasterPublicKeyId>,
    pub pre_signatures_to_create_in_advance: Option<u32>,
    pub max_queue_size: Option<u32>,
}

impl From<KeyConfigInternal> for KeyConfig {
    fn from(src: KeyConfigInternal) -> Self {
        let KeyConfigInternal {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        Self {
            key_id: Some(key_id),
            pre_signatures_to_create_in_advance,
            max_queue_size: Some(max_queue_size),
        }
    }
}

impl TryFrom<KeyConfig> for KeyConfigInternal {
    type Error = String;

    fn try_from(src: KeyConfig) -> Result<Self, Self::Error> {
        let KeyConfig {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        let Some(key_id) = key_id else {
            return Err("KeyConfig.key_id must be specified.".to_string());
        };

        // Ensure presence of `pre_signatures_to_create_in_advance` for keys that require pre-signatures.
        // Note that an invariant ensures that this field is not zero for keys that require pre-signatures.
        if key_id.requires_pre_signatures() && pre_signatures_to_create_in_advance.is_none() {
            return Err(format!(
                "KeyConfig.pre_signatures_to_create_in_advance must be specified for key {key_id}."
            ));
        };
        // Ensure absence of `pre_signatures_to_create_in_advance` for keys that do not require it.
        if !key_id.requires_pre_signatures() && pre_signatures_to_create_in_advance.is_some() {
            return Err(format!(
                "KeyConfig.pre_signatures_to_create_in_advance must not be specified for key {key_id}."
            ));
        };

        let Some(max_queue_size) = max_queue_size else {
            return Err("KeyConfig.max_queue_size must be specified.".to_string());
        };

        Ok(Self {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        })
    }
}

impl From<KeyConfigRequestInternal> for KeyConfigRequest {
    fn from(src: KeyConfigRequestInternal) -> Self {
        let KeyConfigRequestInternal {
            key_config,
            subnet_id,
        } = src;

        let key_config = Some(KeyConfig::from(key_config));

        Self {
            key_config,
            subnet_id: Some(subnet_id),
        }
    }
}

impl TryFrom<KeyConfigRequest> for KeyConfigRequestInternal {
    type Error = String;

    fn try_from(src: KeyConfigRequest) -> Result<Self, Self::Error> {
        let KeyConfigRequest {
            key_config,
            subnet_id,
        } = src;

        let Some(subnet_id) = subnet_id else {
            return Err("KeyConfigRequest.subnet_id must be specified.".to_string());
        };

        let Some(key_config) = key_config else {
            return Err("KeyConfigRequest.key_config must be specified.".to_string());
        };

        let key_config = KeyConfigInternal::try_from(key_config)
            .map_err(|err| format!("Invalid KeyConfigRequest.key_config: {err}"))?;

        Ok(Self {
            key_config,
            subnet_id,
        })
    }
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
            panic!("{LOG_PREFIX}Record for {record_key} not found in registry");
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        mutations::do_recover_subnet::{
            RecoverSubnetPayload, panic_if_record_changed_across_versions,
        },
        registry::Registry,
    };
    use ic_base_types::SubnetId;
    use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, VetKdCurve, VetKdKeyId};
    use ic_protobuf::registry::subnet::v1::{ChainKeyConfig as ChainKeyConfigPb, SubnetRecord};
    use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
    use ic_registry_transport::{delete, upsert};
    use ic_test_utilities_types::ids::subnet_test_id;

    fn get_default_recover_subnet_payload(subnet_id: SubnetId) -> RecoverSubnetPayload {
        RecoverSubnetPayload {
            subnet_id: subnet_id.get(),
            height: 0,
            time_ns: 0,
            state_hash: vec![],
            replacement_nodes: None,
            registry_store_uri: None,
            chain_key_config: None,
        }
    }

    fn setup_registry_with_subnet_holding_key(key_id: &EcdsaKeyId) -> (Registry, SubnetId) {
        let subnet_id_holding_key = subnet_test_id(1001);
        let mut registry = invariant_compliant_registry(0);

        // add a node for our existing subnet that has the ECDSA key
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());

        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfigInternal {
                key_id: MasterPublicKeyId::Ecdsa(key_id.clone()),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        };

        let chain_key_config_pb = ChainKeyConfigPb::from(chain_key_config);
        subnet_record.chain_key_config = Some(chain_key_config_pb);

        let fake_subnet_mutation = add_fake_subnet(
            subnet_id_holding_key,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(fake_subnet_mutation);
        (registry, subnet_id_holding_key)
    }

    #[test]
    fn panic_if_value_changed_across_versions_no_change() {
        let mut registry = invariant_compliant_registry(0);
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
        let mut registry = invariant_compliant_registry(0);
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
        let mut registry = invariant_compliant_registry(0);
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
        let mut registry = invariant_compliant_registry(0);
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
        expected = "Cannot recover subnet 'ge6io-epiam-aaaaa-aaaap-yai': The requested \
        chain key 'ecdsa:Secp256k1:test_key_id' was not found in any subnet."
    )]
    fn do_recover_subnet_should_panic_if_chain_keys_non_existing() {
        let mut registry = invariant_compliant_registry(0);
        let subnet_id = subnet_test_id(1000);

        let mut payload = get_default_recover_subnet_payload(subnet_id);

        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![KeyConfigRequest {
                key_config: Some(KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "test_key_id".to_string(),
                    })),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }),
                subnet_id: Some(subnet_id.get()),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(expected = "Invalid RecoverSubnetPayload.chain_key_config: \
        Invalid InitialChainKeyConfig.key_configs: KeyConfigRequest.subnet_id must be specified.")]
    fn do_recover_subnet_should_panic_if_chain_keys_subnet_not_specified() {
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

        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![KeyConfigRequest {
                key_config: Some(KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }),
                subnet_id: None,
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "Cannot recover subnet 'ge6io-epiam-aaaaa-aaaap-yai': The requested chain key \
        'ecdsa:Secp256k1:test_key_id' is not available in targeted subnet \
        '3ifty-exlam-aaaaa-aaaap-yai'."
    )]
    fn do_recover_subnet_should_panic_if_chain_keys_non_existing_from_requested_subnet() {
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

        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![KeyConfigRequest {
                key_config: Some(KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }),
                subnet_id: Some(subnet_id_to_request_key_from.get()),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "Cannot recover subnet '337oy-l7jam-aaaaa-aaaap-yai': Attempted to recover \
        chain key 'ecdsa:Secp256k1:test_key_id' by requesting it from itself. \
        Subnets cannot recover chain keys from themselves."
    )]
    fn do_recover_subnet_should_panic_if_attempting_to_get_chain_keys_from_itself() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };

        let (mut registry, subnet_id) = setup_registry_with_subnet_holding_key(&key_id);

        // We attempt to get the key from the subnet requesting it
        let mut payload = get_default_recover_subnet_payload(subnet_id);

        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![KeyConfigRequest {
                key_config: Some(KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }),
                subnet_id: Some(subnet_id.get()),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "[Registry] Cannot recover subnet 'ge6io-epiam-aaaaa-aaaap-yai': The requested \
        chain keys [Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"test_key_id\" }), \
        Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"test_key_id\" })] have duplicates"
    )]
    fn do_recover_subnet_should_panic_with_duplicate_chain_keys() {
        // Step 1: Set up a registry holding an ECDSA key.
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        let subnet_id_to_recover = subnet_test_id(1000);
        let (mut registry, subnet_id_holding_key) = setup_registry_with_subnet_holding_key(&key_id);

        // Step 2: try to recover a subnet with the key, but the key appears twice, which should cause a panic.
        let mut payload = get_default_recover_subnet_payload(subnet_id_to_recover);

        let chain_key_request = KeyConfigRequest {
            key_config: Some(KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }),
            subnet_id: Some(subnet_id_holding_key.get()),
        };

        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![chain_key_request; 2],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "KeyConfig.pre_signatures_to_create_in_advance must be specified for key ecdsa:Secp256k1:some_key_name"
    )]
    fn should_panic_when_key_requiring_pre_signatures_is_missing_pre_signatures_to_create() {
        let mut registry = invariant_compliant_registry(0);
        let subnet_id = subnet_test_id(1000);

        let payload = recover_subnet_payload_with_key_config(
            subnet_id,
            MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "some_key_name".to_string(),
            }),
            None,
        );

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "KeyConfig.pre_signatures_to_create_in_advance must not be specified for key vetkd:Bls12_381_G2:some_key_name"
    )]
    fn should_panic_when_key_not_requiring_pre_signatures_has_pre_signatures_to_create() {
        let mut registry = invariant_compliant_registry(0);
        let subnet_id = subnet_test_id(1000);

        let payload = recover_subnet_payload_with_key_config(
            subnet_id,
            MasterPublicKeyId::VetKd(VetKdKeyId {
                curve: VetKdCurve::Bls12_381_G2,
                name: "some_key_name".to_string(),
            }),
            Some(99),
        );

        futures::executor::block_on(registry.do_recover_subnet(payload));
    }

    fn recover_subnet_payload_with_key_config(
        subnet_id: SubnetId,
        key_id: MasterPublicKeyId,
        pre_signatures_to_create_in_advance: Option<u32>,
    ) -> RecoverSubnetPayload {
        let mut payload = get_default_recover_subnet_payload(subnet_id);
        payload.chain_key_config = Some(InitialChainKeyConfig {
            key_configs: vec![KeyConfigRequest {
                key_config: Some(KeyConfig {
                    key_id: Some(key_id),
                    pre_signatures_to_create_in_advance,
                    max_queue_size: Some(155),
                }),
                subnet_id: Some(subnet_id.get()),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });
        payload
    }
}
