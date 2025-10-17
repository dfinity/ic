use candid::Nat;
use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType::Running},
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_root::change_canister::AddCanisterRequest;
use ic_nns_common::types::NeuronId;
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::nns::v1::NnsCanisterRecords;
use ic_registry_keys::make_nns_canister_records_key;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_types::CanisterId;
use std::convert::TryFrom;

#[test]
fn add_nns_canister_via_governance_proposal() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let name = "add_nns_canister_via_governance_proposal".to_string();

        let add_canister_request = AddCanisterRequest {
            name: name.clone(),
            wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
            arg: vec![],
            memory_allocation: Some(Nat::from(12345678_u32)),
            compute_allocation: Some(Nat::from(12_u8)),
            initial_cycles: 1 << 45,
        };

        // Submitting a proposal also implicitly records a vote from the proposer,
        // which with TEST_NEURON_1 is enough to trigger execution.
        let proposal_id = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::NnsCanisterInstall,
            add_canister_request,
            "<proposal created by add_nns_canister_via_governance_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status,
            ProposalStatus::Executed as i32
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert!(pending_proposals.is_empty());

        // Now check whether the callback mutated the registry.
        let nns_canister_records: NnsCanisterRecords = get_value_or_panic(
            &nns_canisters.registry,
            make_nns_canister_records_key().as_bytes(),
        )
        .await;
        let new_canister_record = nns_canister_records.canisters.get(&name).unwrap();
        let new_canister_id =
            CanisterId::try_from(new_canister_record.id.clone().unwrap()).unwrap();

        let status: CanisterStatusResult = nns_canisters
            .root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(new_canister_id),
            )
            .await
            .unwrap();
        assert_eq!(status.status, Running, "{status:?}");

        Ok(())
    })
}
