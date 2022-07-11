use crate::state_test_helpers::{query, update};
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
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_type: i32::from(SnsCanisterType::Governance),
    }
}

/// Get an SnsWasm to use in tests
pub fn test_wasm1() -> SnsWasm {
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 2, 0, 0, 0],
        canister_type: i32::from(SnsCanisterType::Ledger),
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
    sns_wasm_canister_id: CanisterId,
    sns_init_payload: SnsInitPayload,
) -> DeployNewSnsResponse {
    let response = update(
        env,
        sns_wasm_canister_id,
        "deploy_new_sns",
        Encode!(&DeployNewSnsRequest {
            sns_init_payload: Some(sns_init_payload)
        })
        .unwrap(),
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
        "rosetta-api/ledger_canister",
        "ledger-canister",
        &[],
    );
    SnsWasm {
        wasm: ledger_wasm.bytes(),
        canister_type: SnsCanisterType::Ledger.into(),
    }
}
