use candid::Principal;
use pocket_ic::{common::rest::DtsFlag, PocketIc, PocketIcBuilder, UserError, WasmResult};
use std::{thread, time::Duration};

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

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

    pic.update_call(can_id, Principal::anonymous(), "run", vec![42u8; arg_size])
}

#[test]
fn test_benchmarking_app_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_application_subnet()
        .build();
    run_very_slow_method(&pic, 1_000_000, DtsFlag::Disabled, 0).unwrap();
}
