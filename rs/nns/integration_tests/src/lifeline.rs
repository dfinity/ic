use canister_test::Project;
use dfn_candid::{candid, candid_one};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_client_sender::Sender;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::{
    init::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    pb::v1::{
        manage_neuron::{Command, NeuronIdOrSubaccount},
        manage_neuron_response::Command as CommandResponse,
        ManageNeuron, ManageNeuronResponse, NnsFunction, ProposalStatus, Vote,
    },
    proposals::proposal_submission::create_external_update_proposal_candid,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, wait_for_final_state, UpgradeRootProposal},
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters},
    state_test_helpers::{nns_governance_make_proposal, setup_nns_canisters, update_with_sender},
};
use ic_state_machine_tests::StateMachine;
use std::time::Duration;

#[test]
fn test_submit_and_accept_root_canister_upgrade_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new().with_test_neurons().build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // The following canister provides a post-upgrade-hook that simply
        // saves the received message into the heap, and then can be queried
        // for it. For simplicity it always deals with 4 bytes.
        let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "msg_arg_data_copy"
            (func $msg_arg_data_copy (param i32 i32 i32)))
          (func $read_back
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 4))
            (call $msg_reply)
          )
          (memory (;0;) 1)
          (export "memory" (memory 0))
          (func $remember (param)
            (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 4)))
          (export "canister_post_upgrade" (func $remember))
          (export "canister_query read_back" (func $read_back)))"#;

        let wasm_module = wat::parse_str(wat).expect("couldn't convert wat -> wasm");

        // check root status with focus on the checksum
        let root_status: CanisterStatusResult = nns_canisters
            .lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(nns_canisters.root.canister_id()),
            )
            .await
            .expect("getting root canister status failed");

        let root_checksum = root_status.module_hash.expect("root canister has no hash");
        assert_ne!(
            root_checksum,
            ic_crypto_sha2::Sha256::hash(wasm_module.clone().as_slice())
        );

        let funny: u32 = 422557101; // just a funny number I came up with
        let magic = funny.to_le_bytes();

        let proposal = create_external_update_proposal_candid(
            "Proposal to upgrade the root canister",
            "",
            "",
            NnsFunction::NnsRootUpgrade,
            UpgradeRootProposal {
                wasm_module: wasm_module.clone(),
                module_arg: magic.to_vec(),
                stop_upgrade_start: true,
            },
        );

        let proposal_submission_response: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: TEST_NEURON_2_ID,
                    })),
                    id: None,
                    command: Some(Command::MakeProposal(Box::new(proposal))),
                },
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await
            .expect("submit root upgrade failed");

        let proposal_id = if let CommandResponse::MakeProposal(resp) =
            proposal_submission_response.command.as_ref().unwrap()
        {
            ProposalId(resp.proposal_id.unwrap().id)
        } else {
            panic!(
                "Unexpected proposal submission response: {:?}",
                proposal_submission_response
            );
        };

        // Should have 1 pending proposals
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

        // check root status again
        let root_status: CanisterStatusResult = nns_canisters
            .lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(nns_canisters.root.canister_id()),
            )
            .await
            .expect("getting root canister status failed");

        let root_checksum = root_status.module_hash.expect("root canister has no hash");
        assert_eq!(
            root_checksum,
            ic_crypto_sha2::Sha256::hash(wasm_module.as_slice())
        );

        let received_magic = nns_canisters
            .root
            .query_("read_back", on_wire::bytes, vec![])
            .await
            .unwrap();

        assert_eq!(magic, received_magic.as_slice());

        Ok(())
    });
}

#[test]
fn test_submit_and_accept_forced_root_canister_upgrade_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new().with_test_neurons().build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let empty_wasm = ic_test_utilities::empty_wasm::EMPTY_WASM;

        // check root status with focus on the checksum
        let root_status: CanisterStatusResult = nns_canisters
            .lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(nns_canisters.root.canister_id()),
            )
            .await
            .expect("getting root canister status failed");

        let root_checksum = root_status.module_hash.expect("root canister has no hash");
        assert_ne!(root_checksum, ic_crypto_sha2::Sha256::hash(empty_wasm));

        let init_arg: &[u8] = &[];

        let proposal = create_external_update_proposal_candid(
            "Proposal to upgrade the root canister",
            "",
            "",
            NnsFunction::NnsRootUpgrade,
            UpgradeRootProposal {
                wasm_module: empty_wasm.to_vec(),
                module_arg: init_arg.to_vec(),
                stop_upgrade_start: false,
            },
        );

        let proposal_submission_response: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: TEST_NEURON_2_ID,
                    })),
                    id: None,
                    command: Some(Command::MakeProposal(Box::new(proposal))),
                },
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await
            .expect("submit root upgrade failed");

        let proposal_id = if let CommandResponse::MakeProposal(resp) =
            proposal_submission_response.command.as_ref().unwrap()
        {
            ProposalId(resp.proposal_id.unwrap().id)
        } else {
            panic!(
                "Unexpected proposal submission response: {:?}",
                proposal_submission_response
            );
        };

        // Should have 1 pending proposals
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

        // check root status again
        let root_status: CanisterStatusResult = nns_canisters
            .lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(nns_canisters.root.canister_id()),
            )
            .await
            .expect("getting root canister status failed");

        let root_checksum = root_status.module_hash.expect("root canister has no hash");
        assert_eq!(root_checksum, ic_crypto_sha2::Sha256::hash(empty_wasm));

        Ok(())
    });
}

#[test]
fn test_lifeline_canister_restarts_root_on_stop_canister_timeout() {
    let mut state_machine = StateMachine::new();

    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Uninstall and reinstall so we get our killer feature from the unstoppable canister
    let _: () = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "uninstall_code",
        candid_one,
        CanisterIdRecord::from(ROOT_CANISTER_ID),
        LIFELINE_CANISTER_ID.get(),
    )
    .unwrap();

    state_machine
        .install_wasm_in_mode(
            ROOT_CANISTER_ID,
            CanisterInstallMode::Install,
            Project::cargo_bin_maybe_from_env("unstoppable-canister", &[]).bytes(),
            vec![],
        )
        .unwrap();

    state_machine.advance_time(Duration::from_secs(1));
    state_machine.tick();

    let root_wasm = Project::cargo_bin_maybe_from_env("root-canister", &[]).bytes();
    let proposal = create_external_update_proposal_candid(
        "Tea. Earl Grey. Hot.",
        "Make It So",
        "",
        NnsFunction::NnsRootUpgrade,
        UpgradeRootProposal {
            stop_upgrade_start: true,
            wasm_module: root_wasm,
            module_arg: vec![],
        },
    );
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    nns_governance_make_proposal(
        &mut state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );

    state_machine.tick();

    let status: CanisterStatusResult = update_with_sender(
        &state_machine,
        LIFELINE_CANISTER_ID,
        "canister_status",
        candid_one,
        ic_management_canister_types::CanisterIdRecord::from(ROOT_CANISTER_ID),
        PrincipalId::new_anonymous(),
    )
    .unwrap();
    // Assert root canister is still in a stopping state
    assert_eq!(status.status, CanisterStatusType::Stopping);
    // After 60 seconds, canister is still trying to stop...
    state_machine.advance_time(Duration::from_secs(60));
    state_machine.tick();

    let status: CanisterStatusResult = update_with_sender(
        &state_machine,
        LIFELINE_CANISTER_ID,
        "canister_status",
        candid_one,
        ic_management_canister_types::CanisterIdRecord::from(ROOT_CANISTER_ID),
        PrincipalId::new_anonymous(),
    )
    .unwrap();
    // Assert root canister is still in a stopping state
    assert_eq!(status.status, CanisterStatusType::Stopping);

    state_machine.advance_time(Duration::from_secs(241));
    state_machine.tick();
    state_machine.tick();

    // Now it should be running
    let status: CanisterStatusResult = update_with_sender(
        &state_machine,
        LIFELINE_CANISTER_ID,
        "canister_status",
        candid_one,
        ic_management_canister_types::CanisterIdRecord::from(ROOT_CANISTER_ID),
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    // Assert root canister is still in a stopping state
    assert_eq!(status.status, CanisterStatusType::Running);
}
