use crate::common::{
    get_deployed_sns_by_proposal_id_unchecked, set_up_state_machine_with_nns,
    EXPECTED_SNS_CREATION_FEE,
};
use canister_test::Wasm;
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::canister_status::CanisterStatusType::Running;
use ic_nervous_system_common::ONE_TRILLION;
use ic_nervous_system_proto::pb::v1::Canister as NervousSystemProtoCanister;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
    SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_test_utils::{
    sns_wasm,
    state_test_helpers::{self, set_controllers, set_up_universal_canister, update_with_sender},
};
use ic_sns_init::pb::v1::{DappCanisters, SnsInitPayload};
use ic_sns_root::{CanisterSummary, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_sns_wasm::{
    pb::v1::{
        DappCanistersTransferResult, DeployNewSnsResponse, SnsCanisterIds, SnsCanisterType,
        SnsWasm, SnsWasmError,
    },
    sns_wasm::SNS_CANISTER_COUNT_AT_INSTALL,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_test_utilities_types::ids::canister_test_id;

pub mod common;

#[test]
fn test_canisters_are_created_and_installed() {
    // Step 1: Set up NNS
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = set_up_state_machine_with_nns();

    // Step 2: Add cycles and canister WASMs to SNS-WASM.
    state_machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);
    let sns_wasms = sns_wasm::add_real_wasms_to_sns_wasms(&state_machine);

    // Step 3: Deploy a new SNS
    let sns_init_payload = SnsInitPayload {
        dapp_canisters: None,
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };
    let deploy_new_sns_response = sns_wasm::deploy_new_sns(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );
    let canister_ids = deploy_new_sns_response.canisters.unwrap();
    let root_canister_id = canister_ids.root.unwrap();
    let governance_canister_id = canister_ids.governance.unwrap();
    let ledger_canister_id = canister_ids.ledger.unwrap();
    let swap_canister_id = canister_ids.swap.unwrap();
    let index_canister_id = canister_ids.index.unwrap();

    // Step 4: Check that the canisters are installed and have the correct controllers and WASM hashes.
    let get_sns_canisters_summary_response: GetSnsCanistersSummaryResponse = update_with_sender(
        &state_machine,
        CanisterId::unchecked_from_principal(root_canister_id),
        "get_sns_canisters_summary",
        candid_one,
        GetSnsCanistersSummaryRequest {
            update_canister_list: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    // Step 4.1: Check root canister status.
    let root_canister_summary = get_sns_canisters_summary_response.root_canister_summary();
    assert_eq!(root_canister_summary.canister_id(), root_canister_id);
    assert_eq!(root_canister_summary.status().status(), Running);
    assert_eq!(
        root_canister_summary.status().controllers(),
        vec![governance_canister_id]
    );
    assert_eq!(
        root_canister_summary.status().module_hash().unwrap(),
        sns_wasms
            .get(&SnsCanisterType::Root)
            .unwrap()
            .sha256_hash()
            .to_vec()
    );

    // Step 4.2: Check governance canister status.
    let governance_canister_summary =
        get_sns_canisters_summary_response.governance_canister_summary();
    assert_eq!(
        governance_canister_summary.canister_id(),
        governance_canister_id
    );
    assert_eq!(governance_canister_summary.status().status(), Running);
    assert_eq!(
        governance_canister_summary.status().controllers(),
        vec![root_canister_id]
    );
    assert_eq!(
        governance_canister_summary.status().module_hash().unwrap(),
        sns_wasms
            .get(&SnsCanisterType::Governance)
            .unwrap()
            .sha256_hash()
            .to_vec()
    );

    // Step 4.3: Check ledger canister status.
    let ledger_canister_summary = get_sns_canisters_summary_response.ledger_canister_summary();
    assert_eq!(ledger_canister_summary.canister_id(), ledger_canister_id);
    assert_eq!(ledger_canister_summary.status().status(), Running);
    assert_eq!(
        ledger_canister_summary.status().controllers(),
        vec![root_canister_id]
    );
    assert_eq!(
        ledger_canister_summary.status().module_hash().unwrap(),
        sns_wasms
            .get(&SnsCanisterType::Ledger)
            .unwrap()
            .sha256_hash()
            .to_vec()
    );

    // Step 4.4: Check swap canister status.
    let swap_canister_summary = get_sns_canisters_summary_response.swap_canister_summary();
    assert_eq!(swap_canister_summary.canister_id(), swap_canister_id);
    assert_eq!(swap_canister_summary.status().status(), Running);
    assert_eq!(
        swap_canister_summary.status().controllers(),
        vec![ROOT_CANISTER_ID.get()]
    );
    assert_eq!(
        swap_canister_summary.status().module_hash().unwrap(),
        sns_wasms
            .get(&SnsCanisterType::Swap)
            .unwrap()
            .sha256_hash()
            .to_vec()
    );

    // Step 4.5: Check index canister status.
    let index_canister_summary = get_sns_canisters_summary_response.index_canister_summary();
    assert_eq!(index_canister_summary.canister_id(), index_canister_id);
    assert_eq!(index_canister_summary.status().status(), Running);
    assert_eq!(
        index_canister_summary.status().controllers(),
        vec![root_canister_id]
    );
    assert_eq!(
        index_canister_summary.status().module_hash().unwrap(),
        sns_wasms
            .get(&SnsCanisterType::Index)
            .unwrap()
            .sha256_hash()
            .to_vec()
    );
}

/// There are not many tests we can deterministically create at this level
/// to simulate failure without creating more sophisticated test harnesses that let us
/// simulate failures executing basic IC00 operations
#[test]
fn test_deploy_cleanup_on_wasm_install_failure() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns();

    // Add cycles to the SNS-W canister to deploy an SNS.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);

    sns_wasm::add_real_wasms_to_sns_wasms(&machine);
    // we add a wasm that will fail with the given payload on installation
    let bad_wasm = SnsWasm {
        wasm: Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes(),
        canister_type: SnsCanisterType::Governance.into(),
        ..SnsWasm::default()
    };
    sns_wasm::add_wasm_via_proposal(&machine, bad_wasm);

    let sns_init_payload = SnsInitPayload {
        dapp_canisters: None,
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );

    let root = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1);
    let governance = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
    let ledger = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
    let swap = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
    let index = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_ids().first().unwrap().get()),
            canisters: Some(SnsCanisterIds {
                root: Some(root.get()),
                ledger: Some(ledger.get()),
                governance: Some(governance.get()),
                swap: Some(swap.get()),
                index: Some(index.get()),
            }),
            // Because of the invalid WASM above (i.e. universal canister) which does not understand
            // the governance init payload, this fails.
            error: Some(SnsWasmError {
                message: "Error installing Governance WASM: Failed to install WASM on canister \
                qsgjb-riaaa-aaaaa-aaaga-cai: error code 5: Error from Canister qsgjb-riaaa-aaaaa-aaaga-cai: \
                Canister called `ic0.trap` with message: did not find blob on stack.\n\
                Consider gracefully handling failures from this canister or altering the canister to \
                handle exceptions. See documentation: \
                http://internetcomputer.org/docs/current/references/execution-errors#trapped-explicitly"
                    .to_string()
            }),
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
            }),
        }
    );

    // No canisters should exist above SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET because we deleted
    // those canisters.
    for i in 1..=5 {
        assert!(
            !machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + i))
        );
    }

    // 5_000_000_000_000 cycles are burned creating the canisters before the failure
    assert_eq!(
        machine.cycle_balance(SNS_WASM_CANISTER_ID),
        EXPECTED_SNS_CREATION_FEE - SNS_CANISTER_COUNT_AT_INSTALL as u128 * (ONE_TRILLION as u128)
    );
}

#[test]
fn test_deploy_adds_cycles_to_target_canisters() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns();

    // Add cycles to the SNS-W canister to deploy an SNS.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine, None);
    // we add a wasm that will fail with the given payload on installation

    let sns_init_payload = SnsInitPayload {
        dapp_canisters: None,
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );

    let root = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1);
    let governance = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
    let ledger = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
    let swap = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
    let index = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_ids()[0].get()),
            canisters: Some(SnsCanisterIds {
                root: Some(*root.get_ref()),
                ledger: Some(*ledger.get_ref()),
                governance: Some(*governance.get_ref()),
                swap: Some(*swap.get_ref()),
                index: Some(*index.get_ref()),
            }),
            error: None,
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
            }),
        }
    );

    // All cycles should have been used and none refunded.
    assert_eq!(machine.cycle_balance(GOVERNANCE_CANISTER_ID), 0);

    let sixth_cycles = EXPECTED_SNS_CREATION_FEE / 6;

    for canister_id in &[root, governance, swap, index] {
        assert!(machine.canister_exists(*canister_id));
        assert_eq!(machine.cycle_balance(*canister_id), sixth_cycles)
    }

    assert!(machine.canister_exists(ledger));
    assert_eq!(machine.cycle_balance(ledger), sixth_cycles * 2);
}

#[test]
fn test_deploy_sns_and_transfer_dapps() {
    // Setup the state machine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns();

    // Add cycles to the SNS-W canister to deploy the SNS
    machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION as u128);

    // Add the Wasms of the SNS canisters to SNS-W
    sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // Create a dapp_canister and add NNS Root as a controller of it
    // But first, generate a few phony canister IDs to make sure the one we use for the dapp canister doesn't collide with NNS canister IDs
    set_up_universal_canister(&machine, None);
    set_up_universal_canister(&machine, None);
    set_up_universal_canister(&machine, None);
    let dapp_canister = set_up_universal_canister(&machine, None);
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        dapp_canister,
        vec![ROOT_CANISTER_ID.get()],
    );

    // Add the dapp to the SnsInitPayload
    let sns_init_payload = SnsInitPayload {
        dapp_canisters: Some(DappCanisters {
            canisters: vec![NervousSystemProtoCanister {
                id: Some(dapp_canister.get()),
            }],
        }),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };
    let proposal_id = *sns_init_payload.nns_proposal_id.as_ref().unwrap();

    // Call the code under test
    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );

    let root_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);
    let governance_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6);
    let ledger_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 7);
    let swap_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 8);
    let index_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 9);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_id().get()),
            canisters: Some(SnsCanisterIds {
                governance: Some(governance_canister_id.get()),
                root: Some(root_canister_id.get()),
                ledger: Some(ledger_canister_id.get()),
                swap: Some(swap_canister_id.get()),
                index: Some(index_canister_id.get()),
            }),
            error: None,
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![NervousSystemProtoCanister::new(
                    dapp_canister.get()
                )],
            }),
        }
    );

    let canisters_returned = response.canisters.unwrap();
    let root_canister_principal = canisters_returned.root.unwrap();

    let response: GetSnsCanistersSummaryResponse = update_with_sender(
        &machine,
        CanisterId::unchecked_from_principal(root_canister_principal),
        "get_sns_canisters_summary",
        candid_one,
        GetSnsCanistersSummaryRequest {
            update_canister_list: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    assert_eq!(response.dapps.len(), 1);
    let &CanisterSummary {
        canister_id: actual_dapp_canister,
        status: _,
    } = response.dapps.first().unwrap();

    assert_eq!(actual_dapp_canister, Some(dapp_canister.get()));

    // Make sure the recorded DeployedSns matches the ProposalId in the SnsInitPayload
    let deployed_sns = get_deployed_sns_by_proposal_id_unchecked(&machine, proposal_id);

    assert_eq!(
        deployed_sns.governance_canister_id,
        Some(governance_canister_id.get())
    );
    assert_eq!(deployed_sns.root_canister_id, Some(root_canister_id.get()));
    assert_eq!(deployed_sns.swap_canister_id, Some(swap_canister_id.get()));
    assert_eq!(
        deployed_sns.ledger_canister_id,
        Some(ledger_canister_id.get())
    );
    assert_eq!(
        deployed_sns.index_canister_id,
        Some(index_canister_id.get())
    );
}
