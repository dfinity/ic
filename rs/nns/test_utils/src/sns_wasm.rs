use crate::ids::TEST_NEURON_1_ID;
use crate::state_test_helpers::{
    query, try_call_with_cycles_via_universal_canister, update, update_with_sender,
};
use candid::{Decode, Encode};
use canister_test::Project;
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_common::types::ProposalId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::manage_neuron::{Command, NeuronIdOrSubaccount};
use ic_nns_governance::pb::v1::{
    manage_neuron_response::Command as CommandResponse, proposal, ExecuteNnsFunction, ManageNeuron,
    ManageNeuronResponse, NnsFunction, Proposal, ProposalInfo, ProposalStatus,
};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetWasmRequest, GetWasmResponse,
    ListDeployedSnsesRequest, ListDeployedSnsesResponse, SnsCanisterType, SnsWasm,
};
use ic_state_machine_tests::StateMachine;
use maplit::hashmap;
use std::collections::HashMap;
use std::time::Duration;

/// Get an SnsWasm with the smallest valid WASM
pub fn smallest_valid_wasm() -> SnsWasm {
    test_wasm(SnsCanisterType::Governance)
}

/// Get an SnsWasm to use in tests
pub fn test_wasm1() -> SnsWasm {
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 2, 0, 0, 0],
        canister_type: i32::from(SnsCanisterType::Ledger),
    }
}
/// Get a valid tiny WASM for use in tests of a particular SnsCanisterType
fn test_wasm(canister_type: SnsCanisterType) -> SnsWasm {
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_type: canister_type.into(),
    }
}

/// Make get_wasm request to a canister in the StateMachine
pub fn get_wasm(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    hash: &[u8; 32],
) -> GetWasmResponse {
    let response_bytes = query(
        env,
        sns_wasm_canister_id,
        "get_wasm",
        Encode!(&GetWasmRequest {
            hash: hash.to_vec()
        })
        .unwrap(),
    )
    .unwrap();

    Decode!(&response_bytes, GetWasmResponse).unwrap()
}

/// Make add_wasm request to a canister in the StateMachine
pub fn add_wasm(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    wasm: SnsWasm,
    hash: &[u8; 32],
) -> AddWasmResponse {
    let response = update(
        env,
        sns_wasm_canister_id,
        "add_wasm",
        Encode!(&AddWasmRequest {
            hash: hash.to_vec(),
            wasm: Some(wasm)
        })
        .unwrap(),
    )
    .unwrap();

    // Ensure we get the expected response
    Decode!(&response, AddWasmResponse).unwrap()
}

/// Make add_wasm request to a canister in the StateMachine
pub fn add_wasm_via_proposal(env: &StateMachine, wasm: SnsWasm, hash: &[u8; 32]) {
    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm),
    };

    let proposal = Proposal {
        title: Some("title".into()),
        summary: "summary".into(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AddSnsWasm as i32,
            payload: Encode!(&payload).expect("Error encoding proposal payload"),
        })),
    };

    let response: ManageNeuronResponse = update_with_sender(
        env,
        GOVERNANCE_CANISTER_ID,
        "manage_neuron",
        candid_one,
        ManageNeuron {
            id: None,
            command: Some(Command::MakeProposal(Box::new(proposal))),
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                id: TEST_NEURON_1_ID,
            })),
        },
        *TEST_NEURON_1_OWNER_PRINCIPAL,
    )
    .unwrap();

    let pid = match response.command.unwrap() {
        CommandResponse::MakeProposal(resp) => ProposalId::from(resp.proposal_id.unwrap()),
        other => panic!("Unexpected response: {:?}", other),
    };

    while get_proposal_info(env, pid).unwrap().status == (ProposalStatus::Open as i32) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Call Governance's get_proposal_info method
fn get_proposal_info(env: &StateMachine, pid: ProposalId) -> Option<ProposalInfo> {
    let response = query(
        env,
        GOVERNANCE_CANISTER_ID,
        "get_proposal_info",
        Encode!(&pid).unwrap(),
    )
    .unwrap();

    Decode!(&response, Option<ProposalInfo>).unwrap()
}

/// Make deploy_new_sns request to a canister in the StateMachine
pub fn deploy_new_sns(
    env: &StateMachine,
    wallet_canister: CanisterId,
    sns_wasm_canister_id: CanisterId,
    sns_init_payload: SnsInitPayload,
    cycles: u128,
) -> DeployNewSnsResponse {
    let response = try_call_with_cycles_via_universal_canister(
        env,
        wallet_canister,
        sns_wasm_canister_id,
        "deploy_new_sns",
        Encode!(&DeployNewSnsRequest {
            sns_init_payload: Some(sns_init_payload)
        })
        .unwrap(),
        cycles,
    )
    .unwrap();

    Decode!(&response, DeployNewSnsResponse).unwrap()
}

/// Make list_deployed_snses request to a canister in the StateMachine
pub fn list_deployed_snses(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
) -> ListDeployedSnsesResponse {
    let response = query(
        env,
        sns_wasm_canister_id,
        "list_deployed_snses",
        Encode!(&ListDeployedSnsesRequest {}).unwrap(),
    )
    .unwrap();

    Decode!(&response, ListDeployedSnsesResponse).unwrap()
}

/// Make get_next_sns_version request to a canister in the StateMachine
pub fn get_next_sns_version(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    request: GetNextSnsVersionRequest,
) -> GetNextSnsVersionResponse {
    let response_bytes = query(
        env,
        sns_wasm_canister_id,
        "get_next_sns_version",
        Encode!(&request).unwrap(),
    )
    .unwrap();

    Decode!(&response_bytes, GetNextSnsVersionResponse).unwrap()
}

/// Adds non-functional wasms to the SNS-WASM canister (to avoid expensive init process in certain tests)
pub fn add_dummy_wasms_to_sns_wasms(machine: &StateMachine) {
    let root_wasm = test_wasm(SnsCanisterType::Root);
    let root_hash = root_wasm.sha256_hash();
    add_wasm_via_proposal(machine, root_wasm, &root_hash);

    let gov_wasm = test_wasm(SnsCanisterType::Governance);
    let gov_hash = gov_wasm.sha256_hash();
    add_wasm_via_proposal(machine, gov_wasm, &gov_hash);

    let ledger_wasm = test_wasm(SnsCanisterType::Ledger);
    let ledger_hash = ledger_wasm.sha256_hash();
    add_wasm_via_proposal(machine, ledger_wasm, &ledger_hash);

    let swap_wasm = test_wasm(SnsCanisterType::Swap);
    let swap_hash = swap_wasm.sha256_hash();
    add_wasm_via_proposal(machine, swap_wasm, &swap_hash);

    let archive_wasm = test_wasm(SnsCanisterType::Archive);
    let archive_hash = archive_wasm.sha256_hash();
    add_wasm_via_proposal(machine, archive_wasm, &archive_hash);
}

/// Adds real SNS wasms to the SNS-WASM canister for more robust tests, and returns
/// a map of those wasms for use in further tests.
pub fn add_real_wasms_to_sns_wasms(machine: &StateMachine) -> HashMap<SnsCanisterType, SnsWasm> {
    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    add_wasm_via_proposal(machine, root_wasm.clone(), &root_hash);

    let gov_wasm = build_governance_sns_wasm();
    let gov_hash = gov_wasm.sha256_hash();
    add_wasm_via_proposal(machine, gov_wasm.clone(), &gov_hash);

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_hash = ledger_wasm.sha256_hash();
    add_wasm_via_proposal(machine, ledger_wasm.clone(), &ledger_hash);

    let swap_wasm = build_swap_sns_wasm();
    let swap_hash = swap_wasm.sha256_hash();
    add_wasm_via_proposal(machine, swap_wasm.clone(), &swap_hash);

    let archive_wasm = build_archive_sns_wasm();
    let archive_hash = archive_wasm.sha256_hash();
    add_wasm_via_proposal(machine, archive_wasm.clone(), &archive_hash);

    hashmap! {
        SnsCanisterType::Root => root_wasm,
        SnsCanisterType::Governance => gov_wasm,
        SnsCanisterType::Ledger => ledger_wasm,
        SnsCanisterType::Swap => swap_wasm,
        SnsCanisterType::Archive => archive_wasm
    }
}

/// Builds the SnsWasm for the root canister.
pub fn build_root_sns_wasm() -> SnsWasm {
    let root_wasm = Project::cargo_bin_maybe_from_env("sns-root-canister", &[]);
    SnsWasm {
        wasm: root_wasm.bytes(),
        canister_type: SnsCanisterType::Root.into(),
    }
}

/// Builds the SnsWasm for the governance canister.
pub fn build_governance_sns_wasm() -> SnsWasm {
    let governance_wasm = Project::cargo_bin_maybe_from_env("sns-governance-canister", &[]);
    SnsWasm {
        wasm: governance_wasm.bytes(),
        canister_type: SnsCanisterType::Governance.into(),
    }
}

/// Builds the SnsWasm for the ledger canister.
pub fn build_ledger_sns_wasm() -> SnsWasm {
    let ledger_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-ledger", &[]);
    SnsWasm {
        wasm: ledger_wasm.bytes(),
        canister_type: SnsCanisterType::Ledger.into(),
    }
}

/// Builds the SnsWasm for the Swap Canister
pub fn build_swap_sns_wasm() -> SnsWasm {
    let swap_wasm = Project::cargo_bin_maybe_from_env("sns-swap-canister", &[]);
    SnsWasm {
        wasm: swap_wasm.bytes(),
        canister_type: SnsCanisterType::Swap.into(),
    }
}

/// Builds the SnsWasm for the Ledger Archive Canister
pub fn build_archive_sns_wasm() -> SnsWasm {
    let archive_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-archive", &[]);
    SnsWasm {
        wasm: archive_wasm.bytes(),
        canister_type: SnsCanisterType::Archive.into(),
    }
}
