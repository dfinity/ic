use candid::Encode;
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, NNS_SUBNET_ID,
};
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet,
        set_up_cycles_minting_canister, set_up_registry_canister, set_up_universal_canister,
    },
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
    subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_node_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest, update};
use ic_test_utilities::types::ids::{node_test_id, user_test_id};
use ic_types::p2p::build_default_gossip_config;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_delete_subnet::DeleteSubnetPayload,
};

#[test]
fn test_subnet_is_only_deleted_when_appropriate() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_pid_2 = node_test_id(997);
        let node_pid_3 = node_test_id(998);
        let node_operator_pid = user_test_id(999);
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(999));
        let application_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(997));
        let second_system_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(998));
        const VERSION_REPLICA_ID: &str = "version_42";

        let connection_endpoint = ConnectionEndpoint {
            ip_addr: "128.0.0.1".to_string(),
            port: 12345,
            protocol: Protocol::Http1 as i32,
        };
        let node_2 = NodeRecord {
            node_operator_id: node_operator_pid.get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint.clone()),
            ..Default::default()
        };
        let node_3 = NodeRecord {
            node_operator_id: node_operator_pid.get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint),
            ..Default::default()
        };

        let application_subnet_cup = CatchUpPackageContents::default();
        let application_subnet_pk = PublicKey::default();
        let application_subnet = SubnetRecord {
            membership: vec![node_pid_2.get().to_vec()],
            subnet_type: i32::from(SubnetType::Application),
            replica_version_id: VERSION_REPLICA_ID.to_string(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            ..Default::default()
        };
        let second_system_subnet_cup = CatchUpPackageContents::default();
        let second_system_subnet_pk = PublicKey::default();
        let second_system_subnet = SubnetRecord {
            membership: vec![node_pid_3.get().to_vec()],
            subnet_type: i32::from(SubnetType::System),
            replica_version_id: VERSION_REPLICA_ID.to_string(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            ..Default::default()
        };

        let subnet_list = SubnetListRecord {
            subnets: vec![
                subnet_id.get().to_vec(),
                application_subnet_id.get().to_vec(),
                second_system_subnet_id.get().to_vec(),
            ],
        };

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        insert(
                            make_node_record_key(node_pid_2).as_bytes().to_vec(),
                            encode_or_panic(&node_2),
                        ),
                        insert(
                            make_node_record_key(node_pid_3).as_bytes().to_vec(),
                            encode_or_panic(&node_3),
                        ),
                        insert(
                            make_subnet_record_key(application_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&application_subnet),
                        ),
                        insert(
                            make_catch_up_package_contents_key(application_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&application_subnet_cup),
                        ),
                        insert(
                            make_crypto_threshold_signing_pubkey_key(application_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&application_subnet_pk),
                        ),
                        insert(
                            make_catch_up_package_contents_key(second_system_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&second_system_subnet_cup),
                        ),
                        insert(
                            make_crypto_threshold_signing_pubkey_key(second_system_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&second_system_subnet_pk),
                        ),
                        insert(
                            make_subnet_record_key(second_system_subnet_id)
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&second_system_subnet),
                        ),
                        update(
                            make_subnet_list_record_key().as_bytes().to_vec(),
                            encode_or_panic(&subnet_list),
                        ),
                    ],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        let _ = set_up_universal_canister(&runtime).await;
        let _ = set_up_universal_canister(&runtime).await;
        // // Install the universal canister in place of the cycles minting canister
        // let fake_cmc = set_up_universal_canister(&runtime).await;
        let cmc = set_up_cycles_minting_canister(
            &runtime,
            CyclesCanisterInitPayload {
                ledger_canister_id: LEDGER_CANISTER_ID,
                governance_canister_id: GOVERNANCE_CANISTER_ID,
                minting_account_id: Some(GOVERNANCE_CANISTER_ID.get().into()),
                last_purged_notification: Some(1),
            },
        )
        .await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it
        assert_eq!(
            fake_governance_canister.canister_id(),
            GOVERNANCE_CANISTER_ID
        );
        assert_eq!(cmc.canister_id(), CYCLES_MINTING_CANISTER_ID);

        let nonexistent_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
        let payload = DeleteSubnetPayload {
            subnet_id: Some(nonexistent_subnet_id.get()),
        };

        // Cannot delete nonexistent Subnet
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let payload = DeleteSubnetPayload {
            subnet_id: Some((*NNS_SUBNET_ID).get()),
        };

        // Cannot delete the NNS Subnet
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let payload = DeleteSubnetPayload {
            subnet_id: Some(subnet_id.get()),
        };

        // Cannot delete the only system Subnet
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let payload = DeleteSubnetPayload {
            subnet_id: Some(application_subnet_id.get()),
        };

        // Deleting application Subnets succeeds
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let payload = DeleteSubnetPayload {
            subnet_id: Some(second_system_subnet_id.get()),
        };

        // Deleting second system Subnet succeeds
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        Ok(())
    })
}
