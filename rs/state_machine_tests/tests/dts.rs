use ic_base_types::PrincipalId;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig};
use ic_types::Cycles;
use std::time::Duration;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

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
                    i32.const {n}
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
                i32.const {n}
                i32.lt_s
                br_if $my_loop
            )
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_update run" (func $run))
        (export "canister_heartbeat" (func $inc))
    )
"#
    );
    wat::parse_str(wat).unwrap()
}

#[test]
fn test_dts() {
    let config = StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    );
    let sm = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_config(Some(config))
        .build();

    // Create a canister.
    let t0 = sm.get_time();
    let can_id = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    let t1 = sm.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Install the very slow canister wasm file on the canister.
    sm.install_existing_canister(can_id, very_slow_wasm(60_000), vec![])
        .unwrap();

    let t0 = sm.get_time();
    sm.execute_ingress_as(PrincipalId::new_anonymous(), can_id, "run", vec![])
        .unwrap();
    let t1 = sm.get_time();
    assert!(t1 >= t0 + Duration::from_nanos(10)); // DTS takes at least 10 rounds
}
