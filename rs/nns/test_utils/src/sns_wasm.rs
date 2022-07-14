use crate::state_test_helpers::{query, try_call_with_cycles_via_universal_canister, update};
use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetWasmRequest, GetWasmResponse,
    ListDeployedSnsesRequest, ListDeployedSnsesResponse, SnsCanisterType, SnsWasm,
};
use ic_state_machine_tests::StateMachine;

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
pub fn add_dummy_wasms_to_sns_wasms(machine: &StateMachine, sns_wasm_canister_id: CanisterId) {
    let root_wasm = test_wasm(SnsCanisterType::Root);
    let root_hash = root_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, root_wasm, &root_hash);

    let gov_wasm = test_wasm(SnsCanisterType::Governance);
    let gov_hash = gov_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, gov_wasm, &gov_hash);

    let ledger_wasm = test_wasm(SnsCanisterType::Ledger);
    let ledger_hash = ledger_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, ledger_wasm, &ledger_hash);
}

/// Adds real SNS wasms to the SNS-WASM canister for more robust tests
pub fn add_real_wasms_to_sns_wasms(machine: &StateMachine, sns_wasm_canister_id: CanisterId) {
    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, root_wasm, &root_hash);

    let gov_wasm = build_governance_sns_wasm();
    let gov_hash = gov_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, gov_wasm, &gov_hash);

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_hash = ledger_wasm.sha256_hash();
    add_wasm(machine, sns_wasm_canister_id, ledger_wasm, &ledger_hash);
}

/// Builds the SnsWasm for the root canister.
pub fn build_root_sns_wasm() -> SnsWasm {
    let root_wasm =
        Project::cargo_bin_maybe_use_path_relative_to_rs("sns/root", "sns-root-canister", &[]);
    SnsWasm {
        wasm: root_wasm.bytes(),
        canister_type: SnsCanisterType::Root.into(),
    }
}

/// Builds the SnsWasm for the governance canister.
pub fn build_governance_sns_wasm() -> SnsWasm {
    let governance_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "sns/governance",
        "sns-governance-canister",
        &[],
    );
    SnsWasm {
        wasm: governance_wasm.bytes(),
        canister_type: SnsCanisterType::Governance.into(),
    }
}

/// Builds the SnsWasm for the ledger canister.
pub fn build_ledger_sns_wasm() -> SnsWasm {
    let ledger_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "rosetta-api/icrc1/ledger",
        "ic-icrc1-ledger",
        &[],
    );
    SnsWasm {
        wasm: ledger_wasm.bytes(),
        canister_type: SnsCanisterType::Ledger.into(),
    }
}
