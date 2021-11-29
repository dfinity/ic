use dfn_candid::candid;

use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client::Sender;

use ic_nns_common::{
    registry::encode_or_panic,
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR};
use ic_nns_governance::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::ids::TEST_NEURON_2_ID;
use ic_nns_test_utils::{
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
    registry::get_value,
};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_types::p2p::{
    build_default_gossip_config, MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_SIZE, MAX_CHUNK_WAIT_MS,
    MAX_DUPLICITY, PFN_EVALUATION_PERIOD_MS, RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS,
    RETRANSMISSION_REQUEST_MS,
};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;

use std::str::FromStr;

#[test]
fn test_submit_and_accept_update_subnet_proposal() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let subnet_id = SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            );
            let initial_subnet_record = SubnetRecord {
                membership: vec![],
                ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 500,
                initial_notary_delay_millis: 1500,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 0,
                dkg_dealings_per_block: 1,
                gossip_config: Some(build_default_gossip_config()),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 7_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 100,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
            };

            let key = make_subnet_record_key(subnet_id);
            let nns_init_payload = NnsInitPayloadsBuilder::new()
                .with_initial_invariant_compliant_mutations()
                .with_test_neurons()
                .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        key.as_bytes().to_vec(),
                        encode_or_panic(&initial_subnet_record),
                    )],
                    preconditions: vec![],
                }])
                .build();
            let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

            let subnet_record_after_setup: SubnetRecord =
                get_value(&nns_canisters.registry, key.as_bytes()).await;

            assert_eq!(subnet_record_after_setup, initial_subnet_record);

            let proposal_payload = UpdateSubnetPayload {
                subnet_id,
                ingress_bytes_per_block_soft_cap: None,
                max_ingress_bytes_per_message: Some(10 * 1024 * 1024),
                max_block_payload_size: None,
                unit_delay_millis: None,
                initial_notary_delay_millis: None,
                dkg_interval_length: Some(10),
                dkg_dealings_per_block: Some(1),
                max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
                max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
                max_duplicity: Some(MAX_DUPLICITY),
                max_chunk_size: Some(MAX_CHUNK_SIZE),
                receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
                pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
                registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
                retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
                advert_best_effort_percentage: None,
                set_gossip_config_to_default: false,
                start_as_nns: None,
                subnet_type: None,
                is_halted: Some(true),
                max_instructions_per_message: None,
                max_instructions_per_round: Some(8_000_000_000),
                max_instructions_per_install_code: None,
                features: None,
                ecdsa_config: None,
                max_number_of_canisters: Some(200),
                ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
                ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
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
                    .status(),
                ProposalStatus::Executed
            );

            // No proposals should be pending now.
            let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
            assert_eq!(pending_proposals, vec![]);

            let subnet_record_after_update: SubnetRecord =
                get_value(&nns_canisters.registry, key.as_bytes()).await;

            assert_eq!(
                subnet_record_after_update,
                SubnetRecord {
                    membership: vec![],
                    ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
                    max_ingress_bytes_per_message: 10 * 1024 * 1024,
                    max_ingress_messages_per_block: 1000,
                    max_block_payload_size: 4 * 1024 * 1024,
                    unit_delay_millis: 500,
                    initial_notary_delay_millis: 1500,
                    replica_version_id: "version_42".to_string(),
                    dkg_interval_length: 10,
                    dkg_dealings_per_block: 1,
                    gossip_config: Some(build_default_gossip_config()),
                    start_as_nns: false,
                    subnet_type: SubnetType::Application.into(),
                    is_halted: true,
                    max_instructions_per_message: 5_000_000_000,
                    max_instructions_per_round: 8_000_000_000,
                    max_instructions_per_install_code: 200_000_000_000,
                    features: None,
                    max_number_of_canisters: 200,
                    ssh_readonly_access: vec!["pub_key_0".to_string()],
                    ssh_backup_access: vec!["pub_key_1".to_string()],
                    ecdsa_config: None,
                }
            );
            Ok(())
        }
    });
}
