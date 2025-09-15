use candid::{Decode, Encode};
use canister_test::*;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_state_machine_tests::StateMachine;

#[test]
fn test_statesync_test_canisters() {
    let env = StateMachine::new();

    let features = [];
    let wasm = Project::cargo_bin_maybe_from_env("statesync-test-canister", &features);
    let canister_id = env
        .install_canister(
            wasm.bytes(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_memory_allocation(8 * 1024 * 1024 * 1024)
                    .build(),
            ),
        )
        .expect("Failed to install canister");

    let result = env
        .query(canister_id, "read_state", Encode!(&0usize).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u8, String>).unwrap();
    assert_eq!(
        val,
        Ok(0),
        "Queried first element of state vector, should have been 0, was {res:?}"
    );

    let result = env
        .execute_ingress(canister_id, "change_state", Encode!(&33u32).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u64, String>).unwrap();
    assert_eq!(
        val,
        Ok(1),
        "Changed state for the first time, result should have been 1, was {res:?}"
    );

    let result = env
        .query(canister_id, "read_state", Encode!(&0usize).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u8, String>).unwrap();
    assert_eq!(
        val,
        Ok(42),
        "Queried 0th element of state vector, should be 42 for seed 33, was {:?}",
        res
    );
}

fn assert_reply(res: WasmResult) -> Vec<u8> {
    match res {
        WasmResult::Reply(res) => res,
        WasmResult::Reject(_) => {
            unreachable!("Unexpected reject, should have been a reply");
        }
    }
}
