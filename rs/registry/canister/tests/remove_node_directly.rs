use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_test_utils::registry::{
    create_subnet_threshold_signing_pubkey_and_cup_mutations, get_committee_signing_key,
    get_dkg_dealing_key, get_idkg_dealing_encryption_key, get_node_record, get_node_signing_key,
    get_transport_tls_certificate, new_node_keys_and_node_id,
};
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_types::{NodeId, ReplicaVersion};
use maplit::btreemap;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::node_management::common::make_add_node_registry_mutations;
use registry_canister::mutations::node_management::do_add_node::connection_endpoint_from_string;
use registry_canister::mutations::node_management::do_remove_node_directly::RemoveNodeDirectlyPayload;

const TEST_NODE_ALLOWANCE: u64 = 5;

#[test]
fn node_is_removed_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
            http: Some(connection_endpoint_from_string("128.0.0.1:4321")),
            ..Default::default()
        };
        let (node_id, _dkg_dealing_encryption_pk, mutation) = init_mutation(&test_node_record);
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(1))
                .push_init_mutate_request(mutation)
                .build(),
        )
        .await;

        // Ensure there is a value for the node and keys
        let node_record = get_node_record(&registry, node_id).await;
        let node_signing_key = get_node_signing_key(&registry, node_id).await;
        let committee_signing_key = get_committee_signing_key(&registry, node_id).await;
        let dkg_dealing_key = get_dkg_dealing_key(&registry, node_id).await;
        let transport_tls_cert = get_transport_tls_certificate(&registry, node_id).await;
        let idkg_dealing_encryption_key = get_idkg_dealing_encryption_key(&registry, node_id).await;
        assert!(node_record.is_some());
        assert!(node_signing_key.is_some());
        assert!(committee_signing_key.is_some());
        assert!(dkg_dealing_key.is_some());
        assert!(transport_tls_cert.is_some());
        assert!(idkg_dealing_encryption_key.is_some());

        let response: Result<(), String> = registry
            .update_from_sender(
                "remove_node_directly",
                candid,
                (prepare_payload(node_id),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Ensure the value for the node and keys  was removed
        let node_record = get_node_record(&registry, node_id).await;
        let node_signing_key = get_node_signing_key(&registry, node_id).await;
        let committee_signing_key = get_committee_signing_key(&registry, node_id).await;
        let dkg_dealing_key = get_dkg_dealing_key(&registry, node_id).await;
        let transport_tls_cert = get_transport_tls_certificate(&registry, node_id).await;
        let idkg_dealing_encryption_key = get_idkg_dealing_encryption_key(&registry, node_id).await;
        assert!(node_record.is_none());
        assert!(node_signing_key.is_none());
        assert!(committee_signing_key.is_none());
        assert!(dkg_dealing_key.is_none());
        assert!(transport_tls_cert.is_none());
        assert!(idkg_dealing_encryption_key.is_none());

        // Ensure the node operator's allowance is incremented correctly
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: TEST_NODE_ALLOWANCE + 1,
                ..Default::default()
            }
        );

        Ok(())
    });
}

#[test]
fn node_cannot_be_removed_by_non_node_operator() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
            http: Some(connection_endpoint_from_string("128.0.0.1:4321")),
            ..Default::default()
        };
        let (node_id, _dkg_dealing_encryption_pk, mutation) = init_mutation(&test_node_record);
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(1))
                .push_init_mutate_request(mutation)
                .build(),
        )
        .await;

        // Anonymous call fails
        let response: Result<(), String> = registry
            .update_("remove_node_directly", candid, (prepare_payload(node_id),))
            .await;
        assert!(response.is_err());

        Ok(())
    });
}

#[test]
fn node_cannot_be_removed_if_in_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
            http: Some(connection_endpoint_from_string("128.0.0.1:4321")),
            ..Default::default()
        };
        let (node_id, dkg_dealing_encryption_pk, mutation) = init_mutation(&test_node_record);
        // Any Principal can be used here
        let test_subnet_id = SubnetId::from(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let test_subnet_record = SubnetRecord {
            membership: vec![node_id.get().to_vec()],
            replica_version_id: ReplicaVersion::default().into(),
            unit_delay_millis: 600,
            ..Default::default()
        };
        let test_subnet_list_record = SubnetListRecord {
            subnets: vec![
                SubnetId::from(PrincipalId::new_subnet_test_id(999))
                    .get()
                    .to_vec(),
                test_subnet_id.get().to_vec(),
            ],
        };

        let mut mutations = vec![
            // Insert Subnet record
            RegistryMutation {
                mutation_type: registry_mutation::Type::Insert as i32,
                key: make_subnet_record_key(test_subnet_id).as_bytes().to_vec(),
                value: test_subnet_record.encode_to_vec(),
            },
            // Overwrite Subnet List
            RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_subnet_list_record_key().as_bytes().to_vec(),
                value: test_subnet_list_record.encode_to_vec(),
            },
        ];
        let mut subnet_threshold_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                test_subnet_id,
                &btreemap!(node_id => dkg_dealing_encryption_pk),
            );
        mutations.append(&mut subnet_threshold_pk_and_cup_mutations);

        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(1))
                .push_init_mutate_request(mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations,
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Call fails as the node is still in a subnet
        let response: Result<(), String> = registry
            .update_from_sender(
                "remove_node_directly",
                candid,
                (prepare_payload(node_id),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // Ensure the node operator's allowance is not incremented
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: TEST_NODE_ALLOWANCE,
                ..Default::default()
            }
        );

        Ok(())
    });
}

fn init_mutation(node_record: &NodeRecord) -> (NodeId, PublicKey, RegistryAtomicMutateRequest) {
    let (valid_pks, node_id) = new_node_keys_and_node_id();
    let dkg_dealing_encryption_public_key = valid_pks.dkg_dealing_encryption_key().clone();
    let mut mutations = make_add_node_registry_mutations(node_id, node_record.clone(), valid_pks);
    // Insert the node's operator
    mutations.push(RegistryMutation {
        mutation_type: registry_mutation::Type::Insert as i32,
        key: make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL)
            .as_bytes()
            .to_vec(),
        value: NodeOperatorRecord {
            node_allowance: TEST_NODE_ALLOWANCE,
            ..Default::default()
        }
        .encode_to_vec(),
    });
    (
        node_id,
        dkg_dealing_encryption_public_key,
        RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        },
    )
}

fn prepare_payload(node_id: NodeId) -> RemoveNodeDirectlyPayload {
    RemoveNodeDirectlyPayload { node_id }
}
