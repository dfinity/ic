use candid::Principal;
use pocket_ic::{common::rest::DtsFlag, PocketIc, PocketIcBuilder, UserError, WasmResult};
use std::{thread, time::Duration};

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

// Canister code incrementing a counter in every heartbeat
// and exporting a query method to read the counter.
const AUTO_PROGRESS_WAT: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $read
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_query read" (func $read))
        (export "canister_heartbeat" (func $inc))
    )
"#;

#[test]
fn test_auto_progress() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the auto progress canister wasm file on the canister.
    let auto_progress_wasm = wat::parse_str(AUTO_PROGRESS_WAT).unwrap();
    pic.install_canister(can_id, auto_progress_wasm, vec![], None);

    // Capture the original value of the counter.
    let old_counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
        Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
        _ => panic!("could not read counter"),
    };

    // Starting auto progress on the IC.
    // Consequently, heartbeats should be executed on the auto progress canister automatically
    // and its counter should increase.
    pic.auto_progress();

    let mut ok = false;
    for _ in 0..100 {
        let counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
            Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
            _ => panic!("could not read counter"),
        };
        if counter > old_counter {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ok {
        panic!("did not observe a counter increase")
    }

    // Stopping auto progress on the IC.
    // The counter should not increase anymore.
    pic.stop_progress();

    // Capture the current value of the counter.
    let cur_counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
        Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
        _ => panic!("could not read counter"),
    };

    for _ in 0..100 {
        let counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
            Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
            _ => panic!("could not read counter"),
        };
        assert_eq!(counter, cur_counter);
        thread::sleep(Duration::from_millis(100));
    }
}

// Canister code with a very slow method.
fn very_slow_wasm(n: u64) -> Vec<u8> {
    let wat = format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $run
            ;; create a local variable and initialize it to 0
            (local $i i32)
            (local $j i32)
            (loop $my_loop
                i32.const 0
                local.set $j
                (loop $my_inner_loop
                    ;; add one to $j
                    local.get $j
                    i32.const 1
                    i32.add
                    local.set $j
                    ;; if $j is less than 200000 branch to loop
                    local.get $j
                    i32.const {}
                    i32.lt_s
                    br_if $my_inner_loop
                )
                ;; add one to $i
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                ;; if $i is less than 200000 branch to loop
                local.get $i
                i32.const {}
                i32.lt_s
                br_if $my_loop
            )
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_update run" (func $run))
        (export "canister_heartbeat" (func $inc))
    )
"#,
        n, n
    );
    wat::parse_str(wat).unwrap()
}

fn run_very_slow_method(
    pic: &PocketIc,
    loop_iterations: u64,
    dts_flag: DtsFlag,
    arg_size: usize,
) -> Result<WasmResult, UserError> {
    // Create a canister.
    let t0 = pic.get_time();
    let can_id = pic.create_canister();
    let t1 = pic.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Charge the canister with 2T cycles.
    pic.add_cycles(can_id, 100 * INIT_CYCLES);

    // Install the very slow canister wasm file on the canister.
    pic.install_canister(can_id, very_slow_wasm(loop_iterations), vec![], None);

    let t0 = pic.get_time();
    let res = pic.update_call(can_id, Principal::anonymous(), "run", vec![42u8; arg_size]);
    let t1 = pic.get_time();
    if let DtsFlag::Enabled = dts_flag {
        assert!(t1 >= t0 + Duration::from_nanos(10)); // DTS takes at least 10 rounds
    } else {
        assert_eq!(t1, t0 + Duration::from_nanos(1)); // update call should take one round, i.e., 1ns without DTS
    }

    res
}

#[test]
fn test_benchmarking_app_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_application_subnet()
        .build();
    run_very_slow_method(&pic, 200_000, DtsFlag::Disabled, 0).unwrap();
}

#[test]
fn test_benchmarking_system_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_system_subnet()
        .build();
    run_very_slow_method(&pic, 200_000, DtsFlag::Disabled, 3_000_000).unwrap();
}

#[test]
fn very_slow_method_on_application_subnet() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();
    run_very_slow_method(&pic, 200_000, DtsFlag::Enabled, 0).unwrap_err();
}

fn test_dts(dts_flag: DtsFlag) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_dts_flag(dts_flag)
        .build();
    run_very_slow_method(&pic, 60_000, dts_flag, 0).unwrap();
}

#[test]
fn test_dts_enabled() {
    test_dts(DtsFlag::Enabled);
}

#[test]
fn test_dts_disabled() {
    test_dts(DtsFlag::Disabled);
}
