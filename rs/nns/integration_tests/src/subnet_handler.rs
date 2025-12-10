use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client_sender::Sender;
use ic_limits::INITIAL_NOTARY_DELAY;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::subnet::v1::{CanisterCyclesCostSchedule, SubnetRecord};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_types::ReplicaVersion;
use prost::Message;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use std::str::FromStr;

#[test]
fn test_submit_and_accept_update_subnet_proposal() {
    state_machine_test_on_nns_subnet(|runtime| {
        async move {
            let subnet_id = SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            );
            let initial_subnet_record = SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 500,
                initial_notary_delay_millis: INITIAL_NOTARY_DELAY.as_millis() as u64,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 0,
                dkg_dealings_per_block: 1,
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: false,
                features: None,
                max_number_of_canisters: 100,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                chain_key_config: None,
                canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
                recalled_replica_version_ids: vec![],
            };

            let key = make_subnet_record_key(subnet_id);
            let nns_init_payload = NnsInitPayloadsBuilder::new()
                .with_initial_invariant_compliant_mutations()
                .with_test_neurons()
                .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        key.as_bytes(),
                        initial_subnet_record.encode_to_vec(),
                    )],
                    preconditions: vec![],
                }])
                .build();
            let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

            let subnet_record_after_setup: SubnetRecord =
                get_value_or_panic(&nns_canisters.registry, key.as_bytes()).await;

            assert_eq!(subnet_record_after_setup, initial_subnet_record);

            let proposal_payload = UpdateSubnetPayload {
                subnet_id,
                max_ingress_bytes_per_message: Some(10 * 1024 * 1024),
                max_ingress_messages_per_block: None,
                max_block_payload_size: None,
                unit_delay_millis: None,
                initial_notary_delay_millis: None,
                dkg_interval_length: Some(10),
                dkg_dealings_per_block: Some(1),
                start_as_nns: None,
                subnet_type: None,
                is_halted: Some(true),
                halt_at_cup_height: Some(true),
                features: None,
                max_number_of_canisters: Some(200),
                ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
                ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
                chain_key_config: None,
                chain_key_signing_enable: None,
                chain_key_signing_disable: None,
                // Deprecated section follows
                max_artifact_streams_per_peer: None,
                max_chunk_wait_ms: None,
                max_duplicity: None,
                max_chunk_size: None,
                receive_check_cache_size: None,
                pfn_evaluation_period_ms: None,
                registry_poll_period_ms: None,
                retransmission_request_ms: None,
                set_gossip_config_to_default: Default::default(),
            };

            let proposal_id: ProposalId = submit_external_update_proposal(
                &nns_canisters.governance,
                Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
                NeuronId(TEST_NEURON_2_ID),
                NnsFunction::UpdateConfigOfSubnet,
                proposal_payload,
                "<proposal created by test_submit_and_accept_update_subnet_proposal>".to_string(),
                "".to_string(),
            )
            .await;

            // Should have 1 pending proposal.
            let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
            assert_eq!(pending_proposals.len(), 1);

            // Cast votes.
            let input = (TEST_NEURON_1_ID, proposal_id, Vote::Yes);
            let _result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "forward_vote",
                    candid,
                    input,
                    &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
                )
                .await
                .expect("Vote failed");

            // Wait for the proposal to be accepted and executed.
            assert_eq!(
                wait_for_final_state(&nns_canisters.governance, proposal_id)
                    .await
                    .status,
                ProposalStatus::Executed as i32
            );

            // No proposals should be pending now.
            let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
            assert_eq!(pending_proposals, vec![]);

            let subnet_record_after_update: SubnetRecord =
                get_value_or_panic(&nns_canisters.registry, key.as_bytes()).await;

            assert_eq!(
                subnet_record_after_update,
                SubnetRecord {
                    membership: vec![],
                    max_ingress_bytes_per_message: 10 * 1024 * 1024,
                    max_ingress_messages_per_block: 1000,
                    max_block_payload_size: 4 * 1024 * 1024,
                    unit_delay_millis: 500,
                    initial_notary_delay_millis: INITIAL_NOTARY_DELAY.as_millis() as u64,
                    replica_version_id: ReplicaVersion::default().into(),
                    dkg_interval_length: 10,
                    dkg_dealings_per_block: 1,
                    start_as_nns: false,
                    subnet_type: SubnetType::Application.into(),
                    is_halted: true,
                    halt_at_cup_height: true,
                    features: None,
                    max_number_of_canisters: 200,
                    ssh_readonly_access: vec!["pub_key_0".to_string()],
                    ssh_backup_access: vec!["pub_key_1".to_string()],
                    chain_key_config: None,
                    canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
                    recalled_replica_version_ids: vec![],
                }
            );
            Ok(())
        }
    });
}
