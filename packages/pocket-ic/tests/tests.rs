use candid::{encode_one, Principal};
use pocket_ic::{common::blob::BlobCompression, PocketIc, WasmResult};
use std::{io::Read, time::SystemTime};

#[test]
fn test_get_and_set_and_advance_time() {
    let pic = PocketIc::new();
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
    let pic = PocketIc::new();
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
    let pic = PocketIc::new();
    let id = pic.instance_id;
    assert_eq!(PocketIc::list_instances()[id], "Available".to_string());
    drop(pic);
    assert_eq!(PocketIc::list_instances()[id], "Deleted".to_string());
}

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

fn call_counter_can(ic: &PocketIc, can_id: Principal, method: &str) -> WasmResult {
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
    let pic = PocketIc::new();
    let _canister_id = pic.create_canister(None);

    pic.create_checkpoint();
    // todo: read from graph and assert
}

#[test]
fn test_tick() {
    let pic = PocketIc::new();
    pic.tick();
}

#[test]
fn test_set_and_get_stable_memory_not_compressed() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister(None);
    pic.add_cycles(canister_id, 1_000_000_000_000_000_000);
    let wasm_path = std::env::var_os("COUNTER_WASM").expect("Missing counter wasm file");
    let counter_wasm = std::fs::read(wasm_path).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    let data = "deadbeef".as_bytes().to_vec();
    pic.set_stable_memory(canister_id, data.clone(), BlobCompression::NoCompression);

    let read_data = pic.get_stable_memory(canister_id);
    assert_eq!(data, read_data[..8]);
}

#[test]
fn test_set_and_get_stable_memory_compressed() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister(None);
    pic.add_cycles(canister_id, 1_000_000_000_000_000_000);
    let wasm_path = std::env::var_os("COUNTER_WASM").expect("Missing counter wasm file");
    let counter_wasm = std::fs::read(wasm_path).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    let data = "decafbad".as_bytes().to_vec();
    let mut compressed_data = Vec::new();
    let mut gz = flate2::read::GzEncoder::new(&data[..], flate2::Compression::default());
    gz.read_to_end(&mut compressed_data).unwrap();

    pic.set_stable_memory(canister_id, compressed_data.clone(), BlobCompression::Gzip);

    let read_data = pic.get_stable_memory(canister_id);
    assert_eq!(data, read_data[..8]);
}
