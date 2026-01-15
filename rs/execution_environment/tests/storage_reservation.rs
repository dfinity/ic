use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_types::{CanisterId, Cycles};

const T: u128 = 1_000_000_000_000;

fn reserved_cycles_memory_grow_to_full_capacity<F>(
    grow: F,
    num_canisters: usize,
    expected_reserved_cycles: u128,
) where
    F: Fn(&StateMachine, CanisterId),
{
    // Create application subnet `StateMachine`.
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let execution_config = ExecutionConfig::default();
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .build();

    // We create a few universal canisters with a lot of cycles and reserved cycles limit effectively turned off
    // (set to the full amount of initial cycles).
    let mut canisters = vec![];
    let initial_cycles = Cycles::from(u128::MAX / 2);
    let settings = CanisterSettingsArgsBuilder::new()
        .with_reserved_cycles_limit(initial_cycles.get())
        .build();
    for _ in 0..num_canisters {
        let canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                Some(settings.clone()),
                initial_cycles,
            )
            .unwrap();
        canisters.push(canister_id);
    }

    // We grow memory usage of the canisters as much as possible.
    for canister_id in &canisters {
        grow(&env, *canister_id);
    }

    // We compute the total amount of reserved cycles across all canisters.
    let reserved_cycles: u128 = canisters
        .iter()
        .map(|canister_id| {
            env.canister_status(*canister_id)
                .unwrap()
                .unwrap()
                .reserved_cycles()
        })
        .sum();
    assert!(
        expected_reserved_cycles <= reserved_cycles
            && reserved_cycles <= expected_reserved_cycles + T,
        "reserved: {reserved_cycles}, expected (rounded down to T cycles): {expected_reserved_cycles}"
    );

    // Ensure that no more significant amount of memory can be taken on this subnet
    // (a universal canister cannot even be installed).
    let err = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            initial_cycles,
        )
        .unwrap_err();
    // If this fails, then `num_canisters` might have to be increased to fill up the entire subnet.
    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
}

#[test]
fn reserved_cycles_stable_memory_grow_to_full_capacity() {
    let stable_grow = |env: &StateMachine, canister_id: CanisterId| {
        // Reserve in pretty small steps to keep the number of reserved cycles small.
        let mut pages = 1 << 16;
        loop {
            let res = env.execute_ingress(
                canister_id,
                "update",
                wasm()
                    .stable64_grow(pages)
                    .int64_to_blob()
                    .append_and_reply()
                    .build(),
            );
            // if `ic0.stable64_grow` returns -1 (i.e., fails)
            if res
                == Ok(WasmResult::Reply(vec![
                    255, 255, 255, 255, 255, 255, 255, 255,
                ]))
            {
                if pages == 1 {
                    // We cannot grow stable memory by any single WASM page => we're done.
                    break;
                } else {
                    // Try growing memory allocation in smaller steps.
                    pages >>= 1;
                }
            }
        }
    };

    // The total amount of reserved cycles to claim the full subnet memory capacity.
    const NUM_CANISTERS: usize = 5; // we need multiple canisters since the stable memory of a single canister cannot fill the subnet
    const EXPECTED_RESERVED_CYCLES: u128 = 24_954 * T;
    reserved_cycles_memory_grow_to_full_capacity(
        stable_grow,
        NUM_CANISTERS,
        EXPECTED_RESERVED_CYCLES,
    );
}

#[test]
fn reserved_cycles_memory_allocation_grow_to_full_capacity() {
    let ic00_grow = |env: &StateMachine, canister_id: CanisterId| {
        // Set memory allocation to `total` WASM pages.
        let mut total = 0;
        // `pages` specify the increase of memory allocation in WASM pages at a time.
        // We use a very large initial value to reserve a lot of memory at once in this test.
        let mut pages = 1 << 47; // `1 << 63` bytes
        loop {
            let settings = CanisterSettingsArgsBuilder::new()
                .with_memory_allocation((total + pages) << 16) // memory allocation is in bytes
                .build();
            let res = env.update_settings(&canister_id, settings);
            if res.is_err() {
                if pages == 1 {
                    // We cannot grow memory allocation by any single WASM page => we're done.
                    break;
                } else {
                    // Try growing memory allocation in smaller steps.
                    pages >>= 1;
                }
            } else {
                // We successfully grew memory allocation.
                total += pages;
            }
        }
    };

    // The total amount of reserved cycles to claim the full subnet memory capacity
    // while reserving a lot of memory at once.
    const NUM_CANISTERS: usize = 1; // a single canister can fill the subnet with its memory allocation
    const EXPECTED_RESERVED_CYCLES: u128 = 35_135 * T;
    reserved_cycles_memory_grow_to_full_capacity(
        ic00_grow,
        NUM_CANISTERS,
        EXPECTED_RESERVED_CYCLES,
    );
}
