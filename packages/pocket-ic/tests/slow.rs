use candid::Principal;
use pocket_ic::{common::rest::DtsFlag, PocketIc, PocketIcBuilder, UserError, WasmResult};
use std::time::Duration;

// 200T cycles
const INIT_CYCLES: u128 = 200_000_000_000_000;

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
                    ;; if $j is less than ... branch to loop
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
                ;; if $i is less than ... branch to loop
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

    // Charge the canister with 200T cycles.
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the very slow canister wasm on the canister.
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

fn instruction_limit_exceeded(dts_flag: DtsFlag) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_dts_flag(dts_flag)
        .build();

    // Create a canister.
    let can_id = pic.create_canister();

    // Charge the canister with 200T cycles.
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the very slow canister wasm on the canister.
    pic.install_canister(can_id, very_slow_wasm(200_000), vec![], None);

    let res = pic
        .update_call(can_id, Principal::anonymous(), "run", vec![])
        .unwrap_err();
    assert!(res.description.contains(
        "Canister exceeded the limit of 40000000000 instructions for single message execution."
    ));
}

#[test]
fn test_instruction_limit_exceeded_no_dts() {
    instruction_limit_exceeded(DtsFlag::Disabled);
}

#[test]
fn test_instruction_limit_exceeded_dts() {
    instruction_limit_exceeded(DtsFlag::Enabled);
}
