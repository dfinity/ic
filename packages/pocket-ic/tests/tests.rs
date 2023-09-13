use candid::{encode_one, Principal};
use pocket_ic::{PocketIc, WasmResult};

// tests in one file may run concurrently
// test sets from different files run in sequence
#[test]
fn test_counter_canister() {
    let pic = PocketIc::new();

    let can_id = pic.create_canister(None);
    pic.add_cycles(can_id, 1_000_000_000_000_000_000);
    let wasm_path = std::env::var_os("COUNTER_WASM").expect("Missing counter wasm file");
    let counter_wasm = std::fs::read(wasm_path).unwrap();
    pic.install_canister(can_id, counter_wasm, vec![], None);

    let reply = call_counter_can(&pic, can_id, "read");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![1, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![2, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "read");
    assert_eq!(reply, WasmResult::Reply(vec![2, 0, 0, 0]));
}

#[test]
fn test_snapshot() {
    let pic = PocketIc::new();

    let can_id = pic.create_canister(None);
    pic.add_cycles(can_id, 1_000_000_000_000_000_000);
    let wasm_path = std::env::var_os("COUNTER_WASM").expect("Missing counter wasm file");
    let counter_wasm = std::fs::read(wasm_path).unwrap();
    pic.install_canister(can_id, counter_wasm, vec![], None);

    let reply = call_counter_can(&pic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![1, 0, 0, 0]));
    pic.tick_and_create_checkpoint("my_cp");

    let fail = PocketIc::new_from_snapshot("does not exist").err().unwrap();
    assert!(fail
        .to_string()
        .to_lowercase()
        .contains("could not find snapshot"));

    let other_ic = PocketIc::new_from_snapshot("my_cp").unwrap();
    let reply = call_counter_can(&other_ic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![2, 0, 0, 0]));
}

#[test]
fn test_create_and_drop_instances() {
    let pic = PocketIc::new();
    let instance_id = pic.instance_id.clone();
    assert!(PocketIc::list_instances().contains(&instance_id));
    drop(pic);
    assert!(!PocketIc::list_instances().contains(&instance_id));
}

fn call_counter_can(ic: &PocketIc, can_id: Principal, method: &str) -> WasmResult {
    ic.update_call(
        can_id,
        Principal::anonymous(),
        method,
        encode_one(()).unwrap(),
    )
    .expect("Failed to call counter canister")
}
