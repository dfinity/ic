use crate::state_test_helpers::{query, update};
use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_sns_wasm::pb::v1::{
    AddWasm, AddWasmResponse, DeployNewSns, DeployNewSnsResponse, GetWasm, GetWasmResponse,
    ListDeployedSnses, ListDeployedSnsesResponse, SnsCanisterType, SnsWasm,
};
use ic_state_machine_tests::StateMachine;

/// Get an SnsWasm with the smallest valid WASM
pub fn smallest_valid_wasm() -> SnsWasm {
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_type: i32::from(SnsCanisterType::Governance),
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
        Encode!(&GetWasm {
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
        Encode!(&AddWasm {
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
) -> DeployNewSnsResponse {
    let response = update(
        env,
        sns_wasm_canister_id,
        "deploy_new_sns",
        Encode!(&DeployNewSns {}).unwrap(),
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
        Encode!(&ListDeployedSnses {}).unwrap(),
    )
    .unwrap();

    Decode!(&response, ListDeployedSnsesResponse).unwrap()
}
