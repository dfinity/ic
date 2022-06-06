use candid::{Decode, Encode};
use canister_test::{PrincipalId, Project, Wasm};
use dfn_core::CanisterId;
use ic_sns_wasm::pb::v1::add_wasm_response::AddWasmOk;
use ic_sns_wasm::pb::v1::{
    add_wasm_response, AddWasm, AddWasmResponse, GetWasm, GetWasmResponse, SnsCanisterType, SnsWasm,
};
use ic_state_machine_tests::{CanisterSettingsArgs, StateMachine, WasmResult};
use std::vec::Vec;

fn create_canister(
    env: &StateMachine,
    wasm: Wasm,
    initial_payload: Option<Vec<u8>>,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    env.install_canister(
        wasm.bytes(),
        initial_payload.unwrap_or_else(|| Encode!().unwrap()),
        canister_settings,
    )
    .unwrap()
}

fn update(
    env: &StateMachine,
    canister_target: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // move time forward
    env.set_time(std::time::SystemTime::now());
    let result = env
        .execute_ingress(canister_target, method_name, payload)
        .map_err(|e| e.to_string())?;
    match result {
        WasmResult::Reply(v) => Ok(v),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
    }
}

fn query(
    env: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
    sender: Option<PrincipalId>,
) -> Result<Vec<u8>, String> {
    // move time forward
    env.set_time(std::time::SystemTime::now());
    let result = match sender {
        Some(sender) => env.execute_ingress_as(sender, canister, method_name, payload),
        None => env.query(canister, method_name, payload),
    }
    .map_err(|e| e.to_string())?;
    match result {
        WasmResult::Reply(v) => Ok(v),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
    }
}

fn smallest_valid_wasm() -> SnsWasm {
    SnsWasm {
        wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_type: i32::from(SnsCanisterType::Governance),
    }
}

fn get_wasm(env: &StateMachine, canister_id: CanisterId, hash: &[u8; 32]) -> GetWasmResponse {
    let response_bytes = query(
        env,
        canister_id,
        "get_wasm",
        Encode!(&GetWasm {
            hash: hash.to_vec()
        })
        .unwrap(),
        None,
    )
    .unwrap();

    Decode!(&response_bytes, GetWasmResponse).unwrap()
}

fn add_wasm(
    env: &StateMachine,
    canister_id: CanisterId,
    wasm: SnsWasm,
    hash: &[u8; 32],
) -> AddWasmResponse {
    let response = update(
        env,
        canister_id,
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

#[test]
fn test_basic_storage() {
    let env = StateMachine::new();
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );
    // Step 1.b: Build and install canister.
    let sns_wasm_id = create_canister(&env, wasm, None, None);

    let sns_wasm = smallest_valid_wasm();
    let expected_hash = sns_wasm.sha256_hash();

    // Ensure it is not aleady there
    let get_wasm_response = get_wasm(&env, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    // Ensure we get the expected response
    let add_wasm_response = add_wasm(&env, sns_wasm_id, sns_wasm, &expected_hash);
    assert_eq!(
        add_wasm_response,
        AddWasmResponse {
            result: Some(add_wasm_response::Result::Ok(AddWasmOk {
                hash: expected_hash.to_vec()
            }))
        }
    );

    let get_wasm_response = get_wasm(&env, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());
}
