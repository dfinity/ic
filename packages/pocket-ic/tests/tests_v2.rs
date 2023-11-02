use candid::{encode_one, Principal};
use pocket_ic::{PocketIcV2, WasmResult};
use std::time::SystemTime;

#[test]
fn test_get_and_set_and_advance_time() {
    let pic = PocketIcV2::new();
    pic.set_time(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890)
    );
    pic.advance_time(std::time::Duration::from_secs(420));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890 + 420)
    );
}

#[test]
fn test_get_set_cycle_balance() {
    let pic = PocketIcV2::new();
    let canister_id = pic.create_canister(None);
    let balance = pic.cycle_balance(canister_id);
    assert_eq!(balance, 0);
    let new_balance = pic.add_cycles(canister_id, 69_420);
    assert_eq!(new_balance, 69_420);
    let balance = pic.cycle_balance(canister_id);
    assert_eq!(balance, 69_420);
}

#[test]
fn test_create_and_drop_instances() {
    let pic = PocketIcV2::new();
    assert!(PocketIcV2::list_instances().contains(&"Available".to_string()));
    drop(pic);
    assert!(!PocketIcV2::list_instances().contains(&"Available".to_string()));
    assert!(PocketIcV2::list_instances().contains(&"Deleted".to_string()));
}

#[test]
fn test_counter_canister() {
    let pic = PocketIcV2::new();

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

fn call_counter_can(ic: &PocketIcV2, can_id: Principal, method: &str) -> WasmResult {
    ic.update_call(
        can_id,
        Principal::anonymous(),
        method,
        encode_one(()).unwrap(),
    )
    .expect("Failed to call counter canister")
}

#[test]
fn test_checkpoint() {
    let pic = PocketIcV2::new();
    let _canister_id = pic.create_canister(None);

    pic.create_checkpoint();
    // todo: read from graph and assert
}
