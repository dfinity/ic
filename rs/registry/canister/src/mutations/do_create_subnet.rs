use crate::chain_key::{InitialChainKeyConfigInternal, KeyConfigRequestInternal};
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize, Encode};
use dfn_core::api::{call, CanisterId};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_management_canister_types::{
    EcdsaKeyId, MasterPublicKeyId, SetupInitialDKGArgs, SetupInitialDKGResponse,
};
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    subnet::v1::{
        CatchUpPackageContents, ChainKeyConfig as ChainKeyConfigPb, EcdsaConfig as EcdsaConfigPb,
        SubnetFeatures as SubnetFeaturesPb, SubnetRecord,
    },
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_node_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::{
    EcdsaConfig, KeyConfig as KeyConfigInternal, SubnetFeatures, DEFAULT_ECDSA_MAX_QUEUE_SIZE,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use on_wire::bytes;
use prost::Message;
use serde::Serialize;
use std::{collections::HashSet, convert::TryFrom};

impl Registry {
    /// Adds the new subnet to the registry.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for creating a new subnet has been accepted.
    ///
    /// The method must get the registry version from the registry, and then
    /// pass the membership information to ic0's method setup_initial_dkg,
    /// which will then compute the necessary NI-DKG key material for the
    /// subnet. Afterwards, the method will insert this information and the
    /// parameters populated by caller into registry. It is expected that
    /// the rest of the system will take the information from the registry
    /// to actually start the subnet.
    pub async fn do_create_subnet(&mut self, payload: CreateSubnetPayload) {
        println!("{}do_create_subnet: {:?}", LOG_PREFIX, payload);

        self.validate_create_subnet_payload(&payload);

        // The steps are now:
        // 1. SetupInitialDKG gets a list of nodes l and a registry version rv.
        //    A guarantee that it expects is that all nodes in l exist in the
        //    registry at version rv. Thus, we get the latest registry version.
        let request = SetupInitialDKGArgs::new(
            payload.node_ids.clone(),
            RegistryVersion::new(self.latest_version()),
        );

        // 2a. Invoke NI-DKG on ic_00
        let response_bytes = call(
            CanisterId::ic_00(),
            "setup_initial_dkg",
            bytes,
            Encode!(&request).unwrap(),
        )
        .await
        .unwrap();

        let response = SetupInitialDKGResponse::decode(&response_bytes).unwrap();
        println!(
            "{}response from setup_initial_dkg successfully received",
            LOG_PREFIX
        );

        let generated_subnet_id = response.fresh_subnet_id;
        let subnet_id = payload
            .subnet_id_override
            .map(SubnetId::new)
            .unwrap_or(generated_subnet_id);
        println!(
            "{}do_create_subnet: {{payload: {:?}, subnet_id: {}}}",
            LOG_PREFIX, payload, subnet_id
        );

        // 2b. Invoke compute_initial_i_dkg_dealings on ic_00

        // TODO[NNS1-3022]: Stop reading `payload.ecdsa_config` and mutating `payload`.

        // Legacy ECDSA data is used only if there is nothing in `payload.chain_key_config`.
        // Even if legacy ECDSA data is used, it is converted to `InitialChainKeyConfig` here.
        let initial_chain_key_config_from_legacy_source =
            payload.ecdsa_config.clone().map(|ecdsa_initial_config| {
                InitialChainKeyConfigInternal::try_from(ecdsa_initial_config)
                    .expect("Invalid EcdsaInitialConfig")
            });

        let initial_chain_key_config_from_new_source =
            payload
                .chain_key_config
                .clone()
                .map(|initial_chain_key_config| {
                    InitialChainKeyConfigInternal::try_from(initial_chain_key_config)
                        .expect("Invalid InitialChainKeyConfig")
                });

        let initial_chain_key_config = initial_chain_key_config_from_new_source
            .or(initial_chain_key_config_from_legacy_source);

        let receiver_nodes = payload.node_ids.clone();
        let chain_key_initializations = self
            .get_all_initial_i_dkg_dealings_from_ic00(&initial_chain_key_config, receiver_nodes)
            .await;

        // `payload` needs to be canonicalized, ensuring `ecdsa_config: None`.
        let payload = CreateSubnetPayload {
            ecdsa_config: None,
            chain_key_config: initial_chain_key_config.map(InitialChainKeyConfig::from),
            ..payload
        };

        // 3. Create subnet record and associated entries
        let cup_contents = CatchUpPackageContents {
            initial_ni_dkg_transcript_low_threshold: Some(response.low_threshold_transcript_record),
            initial_ni_dkg_transcript_high_threshold: Some(
                response.high_threshold_transcript_record,
            ),
            chain_key_initializations,
            ..Default::default()
        };

        let new_subnet_dkg = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_catch_up_package_contents_key(subnet_id)
                .as_bytes()
                .to_vec(),
            value: cup_contents.encode_to_vec(),
        };

        let new_subnet_threshold_signing_pubkey = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_crypto_threshold_signing_pubkey_key(subnet_id)
                .as_bytes()
                .to_vec(),
            value: response.subnet_threshold_public_key.encode_to_vec(),
        };

        let subnet_record = SubnetRecord::from(payload);

        // 4. Update registry with the new subnet data
        // The subnet data is the new subnet record plus the update to the global
        // subnet list.
        let mut subnet_list_record = self.get_subnet_list_record();
        if subnet_list_record
            .subnets
            .iter()
            .any(|x| *x == subnet_id.get().to_vec())
        {
            panic!(
                "Subnet already present in subnet list record: {:?}",
                subnet_id
            );
        }
        subnet_list_record.subnets.push(subnet_id.get().to_vec());

        let subnet_list_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: make_subnet_list_record_key().as_bytes().to_vec(),
            value: subnet_list_record.encode_to_vec(),
        };

        let new_subnet = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_subnet_record_key(subnet_id).into_bytes(),
            value: subnet_record.encode_to_vec(),
        };

        let routing_table_mutation =
            self.add_subnet_to_routing_table(self.latest_version(), subnet_id);

        let mutations = vec![
            subnet_list_mutation,
            new_subnet,
            new_subnet_dkg,
            new_subnet_threshold_signing_pubkey,
            routing_table_mutation,
        ];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    /// Validates runtime payload values that aren't checked by invariants.
    /// Ensures all nodes for new subnet a) exist and b) are not in another subnet.
    /// Ensure all nodes for new subnet are not already assigned as ApiBoundaryNode.
    /// Ensures that ECDSA keys are not specified using both the (deprecated) `ecdsa_config` and
    ///  the new `chain_key_config` fields.
    /// Ensures that a valid `subnet_id` is specified for `KeyConfigRequest`s.
    /// Ensures that master public keys (a) exist and (b) are present on the requested subnet.
    fn validate_create_subnet_payload(&self, payload: &CreateSubnetPayload) {
        // Verify that all Nodes exist
        payload.node_ids.iter().for_each(|node_id| {
            match self.get(
                make_node_record_key(*node_id).as_bytes(),
                self.latest_version(),
            ) {
                Some(RegistryValue {
                    value,
                    version: _,
                    deletion_marker: _,
                }) => assert_ne!(
                    NodeRecord::decode(value.as_slice()).unwrap(),
                    NodeRecord::default()
                ),
                None => panic!("A NodeRecord for Node with id {} was not found", node_id),
            };
        });

        // Ensure that none of the Nodes are part of another Subnet
        let node_ids_hash_set: HashSet<NodeId> = payload.node_ids.iter().cloned().collect();

        let mut subnet_members: HashSet<NodeId> = HashSet::new();
        self.get_subnet_list_record()
            .subnets
            .iter()
            .map(|s| SubnetId::from(PrincipalId::try_from(s).unwrap()))
            .for_each(|subnet_id| {
                let subnet_record = self.get_subnet_or_panic(subnet_id);
                subnet_record.membership.iter().for_each(|v| {
                    subnet_members.insert(NodeId::from(PrincipalId::try_from(v).unwrap()));
                });
            });

        let intersection = subnet_members
            .intersection(&node_ids_hash_set)
            .copied()
            .collect::<HashSet<_>>();

        if !intersection.is_empty() {
            panic!("Some Nodes are already members of Subnets");
        }

        // Ensure that none of the Nodes are assigned as ApiBoundaryNode
        payload.node_ids.iter().cloned().for_each(|id| {
            if self.get_api_boundary_node_record(id).is_some() {
                panic!("Some Nodes are already assigned as ApiBoundaryNode");
            }
        });

        let prevalidated_initial_chain_key_config =
            match (&payload.ecdsa_config, &payload.chain_key_config) {
                (Some(_), Some(_)) => {
                    panic!(
                        "Deprecated field ecdsa_config cannot be specified with chain_key_config."
                    );
                }
                (Some(ecdsa_initial_config), None) => {
                    let initial_chain_key_config_from_legacy_source =
                        InitialChainKeyConfigInternal::try_from(ecdsa_initial_config.clone())
                            .unwrap_or_else(|err| {
                                panic!(
                            "{}Cannot prevalidate ChainKeyConfig derived from EcdsaInitialConfig: \
                            {}", LOG_PREFIX, err
                        );
                            });
                    Some(initial_chain_key_config_from_legacy_source)
                }
                (None, Some(initial_chain_key_config)) => {
                    let initial_chain_key_config_from_new_source =
                        InitialChainKeyConfigInternal::try_from(initial_chain_key_config.clone())
                            .unwrap_or_else(|err| {
                                panic!("{}Cannot prevalidate ChainKeyConfig: {}", LOG_PREFIX, err);
                            });
                    Some(initial_chain_key_config_from_new_source)
                }
                (None, None) => None,
            };
        if let Some(prevalidated_initial_chain_key_config) = prevalidated_initial_chain_key_config {
            let own_subnet_id = None;
            self.validate_initial_chain_key_config(
                &prevalidated_initial_chain_key_config,
                own_subnet_id,
            )
            .unwrap_or_else(|err| panic!("{}Cannot validate ChainKeyConfig: {}", LOG_PREFIX, err));
        }
    }
}

/// The payload of a proposal to create a new subnet.
///
/// See /rs/protobuf/def/registry/subnet/v1/subnet.proto
/// for the explanation of the fields for the SubnetRecord. All the fields
/// will be used by the subnet canister to create SubnetRecord.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct CreateSubnetPayload {
    /// The list of node IDs that will be part of the new subnet.
    pub node_ids: Vec<NodeId>,

    pub subnet_id_override: Option<PrincipalId>,

    pub max_ingress_bytes_per_message: u64,
    pub max_ingress_messages_per_block: u64,
    pub max_block_payload_size: u64,
    pub unit_delay_millis: u64,
    pub initial_notary_delay_millis: u64,
    pub replica_version_id: std::string::String,
    pub dkg_interval_length: u64,
    pub dkg_dealings_per_block: u64,

    pub start_as_nns: bool,

    pub subnet_type: SubnetType,

    pub is_halted: bool,

    pub features: SubnetFeaturesPb,

    pub max_number_of_canisters: u64,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,

    // Deprecated. Please use `chain_key_config` instead.
    //
    // TODO[NNS1-3022]: Make this field obsolete.
    pub ecdsa_config: Option<EcdsaInitialConfig>,

    pub chain_key_config: Option<InitialChainKeyConfig>,

    // TODO(NNS1-2444): The fields below are deprecated and they are not read anywhere.
    pub ingress_bytes_per_block_soft_cap: u64,
    pub gossip_max_artifact_streams_per_peer: u32,
    pub gossip_max_chunk_wait_ms: u32,
    pub gossip_max_duplicity: u32,
    pub gossip_max_chunk_size: u32,
    pub gossip_receive_check_cache_size: u32,
    pub gossip_pfn_evaluation_period_ms: u32,
    pub gossip_registry_poll_period_ms: u32,
    pub gossip_retransmission_request_ms: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InitialChainKeyConfig {
    pub key_configs: Vec<KeyConfigRequest>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

impl From<InitialChainKeyConfigInternal> for InitialChainKeyConfig {
    fn from(src: InitialChainKeyConfigInternal) -> Self {
        let InitialChainKeyConfigInternal {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;

        let key_configs = key_configs
            .into_iter()
            .map(KeyConfigRequest::from)
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
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
                "Invalid InitialChainKeyConfig.key_configs: {}",
                key_config_validation_errors
            ));
        }

        Ok(Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        })
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyConfigRequest {
    pub key_config: Option<KeyConfig>,
    pub subnet_id: Option<PrincipalId>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
            pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
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

        let Some(pre_signatures_to_create_in_advance) = pre_signatures_to_create_in_advance else {
            return Err(
                "KeyConfig.pre_signatures_to_create_in_advance must be specified.".to_string(),
            );
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
            .map_err(|err| format!("Invalid KeyConfigRequest.key_config: {}", err))?;

        Ok(Self {
            key_config,
            subnet_id,
        })
    }
}

// TODO[NNS1-3022]: Remove this code.
impl TryFrom<EcdsaInitialConfig> for InitialChainKeyConfigInternal {
    type Error = String;

    fn try_from(src: EcdsaInitialConfig) -> Result<Self, Self::Error> {
        let EcdsaInitialConfig {
            quadruples_to_create_in_advance,
            keys,
            max_queue_size,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;
        let pre_signatures_to_create_in_advance = quadruples_to_create_in_advance;
        let max_queue_size = max_queue_size.unwrap_or(DEFAULT_ECDSA_MAX_QUEUE_SIZE);

        let mut errors = vec![];
        let key_configs = keys
            .into_iter()
            .filter_map(|EcdsaKeyRequest { key_id, subnet_id }| {
                let Some(subnet_id) = subnet_id else {
                    errors.push(format!(
                        "EcdsaKeyRequest.subnet_id must be set (.key_id = {:?})",
                        key_id
                    ));
                    return None;
                };
                Some(KeyConfigRequestInternal {
                    key_config: KeyConfigInternal {
                        key_id: MasterPublicKeyId::Ecdsa(key_id),
                        pre_signatures_to_create_in_advance,
                        max_queue_size,
                    },
                    subnet_id,
                })
            })
            .collect();

        if !errors.is_empty() {
            let errors = errors.join(", ");
            return Err(format!("Invalid EcdsaInitialConfig: {}", errors));
        }

        Ok(Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        })
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct EcdsaInitialConfig {
    pub quadruples_to_create_in_advance: u32,
    pub keys: Vec<EcdsaKeyRequest>,
    /// Must be optional for registry candid backwards compatibility.
    pub max_queue_size: Option<u32>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EcdsaKeyRequest {
    pub key_id: EcdsaKeyId,
    pub subnet_id: Option<PrincipalId>,
}

impl From<EcdsaInitialConfig> for EcdsaConfigPb {
    fn from(val: EcdsaInitialConfig) -> Self {
        Self {
            quadruples_to_create_in_advance: val.quadruples_to_create_in_advance,
            key_ids: val
                .keys
                .iter()
                .map(|val| (&val.key_id).into())
                .collect::<Vec<_>>(),
            max_queue_size: val.max_queue_size.unwrap_or(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: val.signature_request_timeout_ns,
            idkg_key_rotation_period_ms: val.idkg_key_rotation_period_ms,
        }
    }
}

impl From<EcdsaInitialConfig> for EcdsaConfig {
    fn from(val: EcdsaInitialConfig) -> Self {
        Self {
            quadruples_to_create_in_advance: val.quadruples_to_create_in_advance,
            key_ids: val
                .keys
                .iter()
                .map(|val| val.key_id.clone())
                .collect::<Vec<_>>(),
            max_queue_size: val.max_queue_size,
            signature_request_timeout_ns: val.signature_request_timeout_ns,
            idkg_key_rotation_period_ms: val.idkg_key_rotation_period_ms,
        }
    }
}

impl From<CreateSubnetPayload> for SubnetRecord {
    fn from(val: CreateSubnetPayload) -> Self {
        SubnetRecord {
            membership: val
                .node_ids
                .iter()
                .map(|id| id.get().into_vec())
                .collect::<Vec<_>>(),
            max_ingress_bytes_per_message: val.max_ingress_bytes_per_message,
            max_ingress_messages_per_block: val.max_ingress_messages_per_block,
            max_block_payload_size: val.max_block_payload_size,
            replica_version_id: val.replica_version_id.clone(),
            unit_delay_millis: val.unit_delay_millis,
            initial_notary_delay_millis: val.initial_notary_delay_millis,
            dkg_interval_length: val.dkg_interval_length,
            dkg_dealings_per_block: val.dkg_dealings_per_block,

            start_as_nns: val.start_as_nns,

            subnet_type: val.subnet_type.into(),

            is_halted: val.is_halted,
            halt_at_cup_height: false,

            features: Some(SubnetFeatures::from(val.features).into()),
            max_number_of_canisters: val.max_number_of_canisters,
            ssh_readonly_access: val.ssh_readonly_access,
            ssh_backup_access: val.ssh_backup_access,

            chain_key_config: val
                .chain_key_config
                .map(|initial_chain_key_config| {
                    InitialChainKeyConfigInternal::try_from(initial_chain_key_config)
                        .expect("Invalid InitialChainKeyConfig")
                })
                .map(ChainKeyConfigPb::from),
            ecdsa_config: None, // obsolete (chain_key_config is used instead now)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use ic_management_canister_types::EcdsaCurve;
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_registry_subnet_features::ChainKeyConfig;
    use ic_types::ReplicaVersion;

    // Note: this can only be unit-tested b/c it fails before we hit inter-canister calls
    // for DKG + ECDSA
    #[test]
    #[should_panic(
        expected = "requested chain key 'ecdsa:Secp256k1:fake_key_id' was not found in any subnet"
    )]
    fn should_panic_if_ecdsa_keys_non_existing() {
        let mut registry = invariant_compliant_registry(0);
        let payload = CreateSubnetPayload {
            replica_version_id: ReplicaVersion::default().into(),
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![EcdsaKeyRequest {
                    key_id: EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "fake_key_id".to_string(),
                    },
                    subnet_id: Some(*TEST_USER2_PRINCIPAL),
                }],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }),
            ..Default::default()
        };

        futures::executor::block_on(registry.do_create_subnet(payload));
    }

    #[test]
    #[should_panic(expected = "EcdsaKeyRequest.subnet_id must be set")]
    fn should_panic_if_ecdsa_keys_subnet_not_specified() {
        // Set up a subnet that has the key but fail to specify subnet_id in request
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let signing_subnet = SubnetId::from(*TEST_USER1_PRINCIPAL);
        let mut registry = invariant_compliant_registry(0);

        // add a node for our existing subnet that has the ECDSA key
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_id.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
        let chain_key_config = ChainKeyConfig::from(ecdsa_config);
        subnet_record.chain_key_config = Some(ChainKeyConfigPb::from(chain_key_config));

        let fake_subnet_mutation = add_fake_subnet(
            signing_subnet,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(fake_subnet_mutation);

        // Make a request for the key from a subnet that does not have the key
        let payload = CreateSubnetPayload {
            replica_version_id: ReplicaVersion::default().into(),
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![EcdsaKeyRequest {
                    key_id,
                    subnet_id: None,
                }],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }),
            ..Default::default()
        };

        futures::executor::block_on(registry.do_create_subnet(payload));
    }

    #[test]
    #[should_panic(
        expected = "The requested chain key 'ecdsa:Secp256k1:fake_key_id' is not available \
        in targeted subnet 'l5ckc-b6p6l-4o5gj-fkfvl-3sq56-7vw6s-d6nof-q4j4j-jzead-nnwim-vqe'"
    )]
    fn should_panic_if_ecdsa_keys_non_existing_from_requested_subnet() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let signing_subnet = SubnetId::from(*TEST_USER1_PRINCIPAL);
        let mut registry = invariant_compliant_registry(0);

        // add a node for our existing subnet that has the ECDSA key
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_id.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
        let chain_key_config = ChainKeyConfig::from(ecdsa_config);
        subnet_record.chain_key_config = Some(ChainKeyConfigPb::from(chain_key_config));

        let fake_subnet_mutation = add_fake_subnet(
            signing_subnet,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(fake_subnet_mutation);

        // Make a request for the key from a subnet that does not have the key
        let payload = CreateSubnetPayload {
            replica_version_id: ReplicaVersion::default().into(),
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![EcdsaKeyRequest {
                    key_id,
                    subnet_id: Some(*TEST_USER2_PRINCIPAL),
                }],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }),
            ..Default::default()
        };

        futures::executor::block_on(registry.do_create_subnet(payload));
    }

    #[test]
    #[should_panic(expected = "The requested chain keys [\
        Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"fake_key_id\" }), \
        Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"fake_key_id\" })] have duplicates")]
    fn test_disallow_duplicate_ecdsa_keys() {
        // Step 1.1: prepare registry.
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Step 1.2: prepare a subnet with an ECDSA key.
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let signing_subnet = SubnetId::from(*TEST_USER1_PRINCIPAL);
        let mut subnet_list_record = registry.get_subnet_list_record();
        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_id.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
        let chain_key_config = ChainKeyConfig::from(ecdsa_config);
        let chain_key_config_pb = ChainKeyConfigPb::from(chain_key_config);
        subnet_record.chain_key_config = Some(chain_key_config_pb);

        let fake_subnet_mutation = add_fake_subnet(
            signing_subnet,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(fake_subnet_mutation);

        // Step 2: Try to create another subnet with duplicate keys, which should panic.
        let key_request = EcdsaKeyRequest {
            key_id,
            subnet_id: Some(*TEST_USER1_PRINCIPAL),
        };
        let payload = CreateSubnetPayload {
            replica_version_id: ReplicaVersion::default().into(),
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![key_request; 2],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }),
            ..Default::default()
        };
        futures::executor::block_on(registry.do_create_subnet(payload));
    }

    // TODO[NNS1-3022]: Replace this test with one that checks that `subnet_record.ecdsa_config`
    // TODO[NNS1-3022]: cannot be set.
    #[test]
    #[should_panic(
        expected = "Deprecated field ecdsa_config cannot be specified with chain_key_config."
    )]
    fn test_disallow_legacy_and_chain_key_ecdsa_config_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        // Make a request for the key from a subnet that does not have the key.
        let payload = CreateSubnetPayload {
            replica_version_id: ReplicaVersion::default().into(),
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![EcdsaKeyRequest {
                    key_id: key_id.clone(),
                    subnet_id: Some(*TEST_USER2_PRINCIPAL),
                }],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                ..Default::default()
            }),
            chain_key_config: Some(InitialChainKeyConfig {
                key_configs: vec![KeyConfigRequest {
                    key_config: Some(KeyConfig {
                        key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                        pre_signatures_to_create_in_advance: Some(1),
                        max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                    }),
                    subnet_id: Some(*TEST_USER2_PRINCIPAL),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        futures::executor::block_on(registry.do_create_subnet(payload));
    }
}
