use canister_test::Project;
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_management_canister_types::{CanisterInstallMode, CanisterStatusType};
use ic_nervous_system_clients::canister_id_record::CanisterIdRecord;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    pb::v1::{
        manage_neuron_response::Command as CommandResponse, NnsFunction, ProposalStatus, Vote,
    },
    proposal_helpers::create_external_update_proposal_candid,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::UpgradeRootProposal,
    state_test_helpers::{
        get_pending_proposals, get_root_canister_status, nns_cast_vote,
        nns_governance_get_proposal_info_as_anonymous, nns_governance_make_proposal,
        nns_wait_for_proposal_execution, setup_nns_canisters, state_machine_builder_for_nns_tests,
        update_with_sender,
    },
};
use std::time::Duration;

#[test]
fn test_submit_and_accept_root_canister_upgrade_proposal() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

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
    let root_status = get_root_canister_status(&state_machine).unwrap();
    let root_checksum = root_status
        .module_hash()
        .expect("root canister has no hash");
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

    let neuron_id = NeuronId {
        id: TEST_NEURON_2_ID,
    };
    let proposal_submission_response = nns_governance_make_proposal(
        &state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );
    let proposal_id = if let CommandResponse::MakeProposal(resp) =
        proposal_submission_response.command.as_ref().unwrap()
    {
        resp.proposal_id.unwrap()
    } else {
        panic!(
            "Unexpected proposal submission response: {:?}",
            proposal_submission_response
        );
    };

    // Should have 1 pending proposals
    let pending_proposals = get_pending_proposals(&state_machine);
    assert_eq!(pending_proposals.len(), 1);

    // Cast votes.
    nns_cast_vote(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        ic_nns_common::pb::v1::NeuronId {
            id: TEST_NEURON_1_ID,
        },
        proposal_id.id,
        Vote::Yes,
    );

    // Wait for the proposal to be accepted and executed.
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);
    let proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
    assert_eq!(
        proposal_info.status(),
        ProposalStatus::Executed,
        "{:#?}",
        proposal_info
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&state_machine);
    assert_eq!(pending_proposals, vec![]);
    // check root status again
    let root_status = get_root_canister_status(&state_machine).unwrap();

    let root_checksum = root_status
        .module_hash()
        .expect("root canister has no hash");
    assert_eq!(
        root_checksum,
        ic_crypto_sha2::Sha256::hash(wasm_module.as_slice())
    );

    let received_magic: Vec<u8> = state_machine
        .query(
            ROOT_CANISTER_ID,
            "read_back",
            candid::encode_args(()).unwrap(),
        )
        .unwrap()
        .bytes();
    assert_eq!(magic, received_magic.as_slice());
}

#[test]
fn test_submit_and_accept_forced_root_canister_upgrade_proposal() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let empty_wasm = ic_test_utilities::empty_wasm::EMPTY_WASM;
    // check root status with focus on the checksum
    let root_status = get_root_canister_status(&state_machine).unwrap();
    let root_checksum = root_status
        .module_hash()
        .expect("root canister has no hash");
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

    let neuron_id = NeuronId {
        id: TEST_NEURON_2_ID,
    };
    let proposal_submission_response = nns_governance_make_proposal(
        &state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );

    let proposal_id = if let CommandResponse::MakeProposal(resp) =
        proposal_submission_response.command.as_ref().unwrap()
    {
        resp.proposal_id.unwrap()
    } else {
        panic!(
            "Unexpected proposal submission response: {:?}",
            proposal_submission_response
        );
    };

    // Should have 1 pending proposals
    let pending_proposals = get_pending_proposals(&state_machine);
    assert_eq!(pending_proposals.len(), 1);

    // Cast votes.
    nns_cast_vote(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        ic_nns_common::pb::v1::NeuronId {
            id: TEST_NEURON_1_ID,
        },
        proposal_id.id,
        Vote::Yes,
    );
    // Wait for the proposal to be accepted and executed.
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);
    let proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
    assert_eq!(
        proposal_info.status(),
        ProposalStatus::Executed,
        "{:#?}",
        proposal_info
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&state_machine);
    assert_eq!(pending_proposals, vec![]);

    // check root status again
    let root_status = get_root_canister_status(&state_machine).unwrap();
    let root_checksum = root_status
        .module_hash()
        .expect("root canister has no hash");
    assert_eq!(root_checksum, ic_crypto_sha2::Sha256::hash(empty_wasm));
}

#[test]
fn test_lifeline_canister_restarts_root_on_stop_canister_timeout() {
    let state_machine = state_machine_builder_for_nns_tests().build();

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
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );

    state_machine.tick();

    let status = get_root_canister_status(&state_machine).unwrap();
    // Assert root canister is still in a stopping state
    assert_eq!(status.status(), CanisterStatusType::Stopping);
    // After 60 seconds, canister is still trying to stop...
    state_machine.advance_time(Duration::from_secs(60));
    state_machine.tick();

    let status = get_root_canister_status(&state_machine).unwrap();
    // Assert root canister is still in a stopping state
    assert_eq!(status.status(), CanisterStatusType::Stopping);

    state_machine.advance_time(Duration::from_secs(241));
    state_machine.tick();
    state_machine.tick();
    state_machine.tick();

    // Now it should be running
    let status = get_root_canister_status(&state_machine).unwrap();
    // Assert root canister is still in a stopping state
    assert_eq!(status.status(), CanisterStatusType::Running);
}
