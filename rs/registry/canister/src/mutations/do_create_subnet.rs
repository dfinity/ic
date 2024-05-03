use std::{collections::HashSet, convert::TryFrom};

use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize, Encode};
use dfn_core::api::{call, CanisterId};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_management_canister_types::{EcdsaKeyId, SetupInitialDKGArgs, SetupInitialDKGResponse};
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    subnet::v1::{
        CatchUpPackageContents, ChainKeyConfig, EcdsaConfig, GossipConfig,
        SubnetFeatures as pbSubnetFeatures, SubnetRecord,
    },
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_node_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::{SubnetFeatures, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

use on_wire::bytes;

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

        // 2b. Invoke compute_initial_ecdsa_dealings on ic_00
        let ecdsa_initializations = self
            .get_all_initial_ecdsa_dealings_from_ic00(
                &payload.ecdsa_config,
                payload.node_ids.clone(),
            )
            .await;

        // 3. Create subnet record and associated entries
        let cup_contents = CatchUpPackageContents {
            initial_ni_dkg_transcript_low_threshold: Some(response.low_threshold_transcript_record),
            initial_ni_dkg_transcript_high_threshold: Some(
                response.high_threshold_transcript_record,
            ),
            ecdsa_initializations,
            ..Default::default()
        };

        let new_subnet_dkg = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_catch_up_package_contents_key(subnet_id)
                .as_bytes()
                .to_vec(),
            value: encode_or_panic(&cup_contents),
        };

        let new_subnet_threshold_signing_pubkey = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_crypto_threshold_signing_pubkey_key(subnet_id)
                .as_bytes()
                .to_vec(),
            value: encode_or_panic(&response.subnet_threshold_public_key),
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
            value: encode_or_panic(&subnet_list_record),
        };

        let new_subnet = RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_subnet_record_key(subnet_id).into_bytes(),
            value: encode_or_panic(&subnet_record),
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

    /// Validates runtime payload values that aren't checked by invariants
    /// Ensures all nodes for new subnet a) exist and b) are not in another subnet
    /// Ensure all nodes for new subnet are not already assigned as ApiBoundaryNode
    /// Ensures that a valid subnet_id is specified for EcdsaKeyRequests
    /// Ensures that ECDSA keys a) exist and b) are present on the requested subnet
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
                    decode_registry_value::<NodeRecord>(value.clone()),
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

        if let Some(ref ecdsa_config) = payload.ecdsa_config {
            match self.validate_ecdsa_initial_config(ecdsa_config, None) {
                Ok(_) => {}
                Err(message) => panic!("{}Cannot create subnet: {}", LOG_PREFIX, message),
            }
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

    // Unused.
    pub ingress_bytes_per_block_soft_cap: u64,
    pub max_ingress_bytes_per_message: u64,
    pub max_ingress_messages_per_block: u64,
    pub max_block_payload_size: u64,
    pub unit_delay_millis: u64,
    pub initial_notary_delay_millis: u64,
    pub replica_version_id: std::string::String,
    pub dkg_interval_length: u64,
    pub dkg_dealings_per_block: u64,

    pub gossip_max_artifact_streams_per_peer: u32,
    pub gossip_max_chunk_wait_ms: u32,
    pub gossip_max_duplicity: u32,
    pub gossip_max_chunk_size: u32,
    pub gossip_receive_check_cache_size: u32,
    pub gossip_pfn_evaluation_period_ms: u32,
    pub gossip_registry_poll_period_ms: u32,
    pub gossip_retransmission_request_ms: u32,

    pub start_as_nns: bool,

    pub subnet_type: SubnetType,

    pub is_halted: bool,

    pub max_instructions_per_message: u64,
    pub max_instructions_per_round: u64,
    pub max_instructions_per_install_code: u64,

    pub features: pbSubnetFeatures,

    pub max_number_of_canisters: u64,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,

    pub ecdsa_config: Option<EcdsaInitialConfig>,
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

impl From<EcdsaInitialConfig> for EcdsaConfig {
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

impl From<CreateSubnetPayload> for SubnetRecord {
    fn from(val: CreateSubnetPayload) -> Self {
        // TODO[NNS1-3006]: Stop updating the ecdsa_config field.
        let ecdsa_config = val.ecdsa_config.map(EcdsaConfig::from);

        // TODO[NNS1-2988]: Take value directly from `CreateSubnetPayload.chain_key_config`.
        let chain_key_config = ecdsa_config.clone().map(ChainKeyConfig::from);

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

            gossip_config: Some(GossipConfig {
                max_artifact_streams_per_peer: val.gossip_max_artifact_streams_per_peer,
                max_chunk_wait_ms: val.gossip_max_chunk_wait_ms,
                max_duplicity: val.gossip_max_duplicity,
                max_chunk_size: val.gossip_max_chunk_size,
                receive_check_cache_size: val.gossip_receive_check_cache_size,
                pfn_evaluation_period_ms: val.gossip_pfn_evaluation_period_ms,
                registry_poll_period_ms: val.gossip_registry_poll_period_ms,
                retransmission_request_ms: val.gossip_retransmission_request_ms,
            }),

            start_as_nns: val.start_as_nns,

            subnet_type: val.subnet_type.into(),

            is_halted: val.is_halted,
            halt_at_cup_height: false,

            max_instructions_per_message: val.max_instructions_per_message,
            max_instructions_per_round: val.max_instructions_per_round,
            max_instructions_per_install_code: val.max_instructions_per_install_code,
            features: Some(SubnetFeatures::from(val.features).into()),
            max_number_of_canisters: val.max_number_of_canisters,
            ssh_readonly_access: val.ssh_readonly_access,
            ssh_backup_access: val.ssh_backup_access,

            chain_key_config,
            ecdsa_config,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use crate::mutations::do_create_subnet::{
        CreateSubnetPayload, EcdsaInitialConfig, EcdsaKeyRequest,
    };
    use ic_base_types::SubnetId;
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
    use ic_types::ReplicaVersion;

    // Note: this can only be unit-tested b/c it fails before we hit inter-canister calls
    // for DKG + ECDSA
    #[test]
    #[should_panic(
        expected = "The requested ECDSA key 'Secp256k1:fake_key_id' was not found in any subnet"
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
        expected = "EcdsaKeyRequest for key 'Secp256k1:fake_key_id' did not specify subnet_id."
    )]
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
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

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
        expected = "The requested ECDSA key 'Secp256k1:fake_key_id' is not available in targeted \
                    subnet 'l5ckc-b6p6l-4o5gj-fkfvl-3sq56-7vw6s-d6nof-q4j4j-jzead-nnwim-vqe'"
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
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

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
    #[should_panic(
        expected = "[Registry] Cannot create subnet: The requested ECDSA key ids [EcdsaKeyId { curve: \
                    Secp256k1, name: \"fake_key_id\" }, EcdsaKeyId { curve: Secp256k1, name: \"fake_key_id\" }] \
                    have duplicates"
    )]
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
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );
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
}
