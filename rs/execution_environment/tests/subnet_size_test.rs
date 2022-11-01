use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SubnetConfig},
};
use ic_ic00_types::CanisterInstallMode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{CanisterSettingsArgs, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::types::messages::SignedIngressBuilder;
use ic_types::{
    messages::SignedIngressContent, ComputeAllocation, Cycles, NumBytes, NumInstructions,
};
use std::time::Duration;

const DEFAULT_CYCLES_PER_NODE: Cycles = Cycles::new(10_000_000_000);
const TEST_CANISTER_INSTALL_EXECUTION_INSTRUCTIONS: u64 = 996_000;

/// This is a canister that keeps a counter on the heap and exposes various test
/// methods. Exposed methods:
///  * "inc"       increment the counter
///  * "read"      read the counter value
///  * "persist"   copy the counter value to stable memory
///  * "load"      restore the counter value from stable memory
///  * "copy_to"   copy the counter value to the specified address on the heap
///  * "read_at"   read a 32-bit integer at the specified address on the heap
///  * "grow_page" grow stable memory by 1 page
///  * "grow_mem"  grow memory by the current counter value
const TEST_CANISTER: &str = r#"
(module
    (import "ic0" "msg_arg_data_copy"
    (func $msg_arg_data_copy (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
    (import "ic0" "stable_read"
    (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "stable_write"
    (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

    (func $inc

    ;; load the old counter value, increment, and store it back
    (i32.store

        ;; store at the beginning of the heap
        (i32.const 0) ;; store at the beginning of the heap

        ;; increment heap[0]
        (i32.add

        ;; the old value at heap[0]
        (i32.load (i32.const 0))

        ;; "1"
        (i32.const 1)
        )
    )
    (call $msg_reply_data_append (i32.const 0) (i32.const 0))
    (call $msg_reply)
    )

    (func $read
    ;; now we copied the counter address into heap[0]
    (call $msg_reply_data_append
        (i32.const 0) ;; the counter address from heap[0]
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $copy_to
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.load (i32.const 4)) (i32.load (i32.const 0)))
    (call $msg_reply)
    )

    (func $read_at
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (call $msg_reply_data_append (i32.load (i32.const 4)) (i32.const 4))
    (call $msg_reply)
    )

    (func $grow_page
    (drop (call $stable_grow (i32.const 1)))
    (call $msg_reply)
    )

    (func $grow_mem
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.const 4)
        (memory.grow (i32.load (i32.const 4))))
    (call $msg_reply_data_append (i32.const 4) (i32.const 4))
    (call $msg_reply)
    )

    (func $persist
    (call $stable_write
        (i32.const 0) ;; offset
        (i32.const 0) ;; src
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $load
    (call $stable_read
        (i32.const 0) ;; dst
        (i32.const 0) ;; offset
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (memory $memory 1)
    (export "memory" (memory $memory))
    (export "canister_query read" (func $read))
    (export "canister_query read_at" (func $read_at))
    (export "canister_update inc" (func $inc))
    (export "canister_update persist" (func $persist))
    (export "canister_update load" (func $load))
    (export "canister_update copy_to" (func $copy_to))
    (export "canister_update grow_page" (func $grow_page))
    (export "canister_update grow_mem" (func $grow_mem))
)"#;

fn simulate_one_gib_per_second_cost(
    subnet_type: SubnetType,
    subnet_size: usize,
    compute_allocation: ComputeAllocation,
) -> Cycles {
    // This function simulates `execute_round` to get the storage cost of 1 GiB for 1 second
    // with a given compute allocation.
    // Since the duration between allocation charges may not be equal to 1 second
    // the final cost is scaled proportionally.
    let one_gib: u64 = 1 << 30;
    let one_second = Duration::from_secs(1);

    let env = StateMachineBuilder::new()
        .with_use_cost_scaling_flag(true)
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .build();
    let canister_id = env.create_canister_with_cycles(
        DEFAULT_CYCLES_PER_NODE * subnet_size,
        Some(CanisterSettingsArgs {
            controller: None,
            controllers: None,
            compute_allocation: Some(candid::Nat::from(compute_allocation.as_percent())),
            memory_allocation: Some(candid::Nat::from(one_gib)),
            freezing_threshold: None,
        }),
    );

    // The time delta is long enough that allocation charging should be triggered.
    let duration_between_allocation_charges = Duration::from_secs(10);
    env.advance_time(duration_between_allocation_charges);

    let balance_before = env.cycle_balance(canister_id);
    env.tick();
    let balance_after = env.cycle_balance(canister_id);

    // Scale the cost from a defined in config value to a 1 second duration.
    let cost = balance_before - balance_after;
    let one_second_cost =
        (cost * one_second.as_millis()) / duration_between_allocation_charges.as_millis();

    Cycles::from(one_second_cost)
}

/// Specifies fees to keep in `CyclesAccountManagerConfig` for specific operations,
/// eg. `ingress induction cost`, `execution cost` etc.
enum KeepFeesFilter {
    ExecutionCost,
    IngressInductionCost,
}

/// Helps to distinguish different costs that are withdrawn within the same execution round.
/// All irrelevant fees in `CyclesAccountManagerConfig` are dropped to zero.
/// This hack allows to calculate operation cost by comparing canister's balance before and after
/// execution round.
fn apply_filter(
    initial_config: CyclesAccountManagerConfig,
    filter: KeepFeesFilter,
) -> CyclesAccountManagerConfig {
    let mut filtered_config = CyclesAccountManagerConfig::system_subnet();
    match filter {
        KeepFeesFilter::ExecutionCost => {
            filtered_config.update_message_execution_fee =
                initial_config.update_message_execution_fee;
            filtered_config.ten_update_instructions_execution_fee =
                initial_config.ten_update_instructions_execution_fee;
            filtered_config
        }
        KeepFeesFilter::IngressInductionCost => {
            filtered_config.ingress_message_reception_fee =
                initial_config.ingress_message_reception_fee;
            filtered_config.ingress_byte_reception_fee = initial_config.ingress_byte_reception_fee;
            filtered_config
        }
    }
}

/// Create a `SubnetConfig` with a redacted `CyclesAccountManagerConfig` to have only the fees
/// for specific operation.
fn filtered_subnet_config(subnet_type: SubnetType, filter: KeepFeesFilter) -> SubnetConfig {
    let mut subnet_config = match subnet_type {
        SubnetType::Application => SubnetConfig::default_application_subnet(),
        SubnetType::System => SubnetConfig::default_system_subnet(),
        SubnetType::VerifiedApplication => SubnetConfig::default_verified_application_subnet(),
    };
    subnet_config.cycles_account_manager_config =
        apply_filter(subnet_config.cycles_account_manager_config, filter);

    subnet_config
}

fn simulate_execute_install_code_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    // This function simulates `execute_round` to get the cost of installing code,
    // including charging and refunding execution cycles.
    // Filtered `CyclesAccountManagerConfig` is used to avoid irrelevant costs,
    // eg. ingress induction cost.
    let env = StateMachineBuilder::new()
        .with_use_cost_scaling_flag(true)
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_config(Some(StateMachineConfig::new(
            filtered_subnet_config(subnet_type, KeepFeesFilter::ExecutionCost),
            HypervisorConfig::default(),
        )))
        .build();
    let canister_id = env.create_canister_with_cycles(DEFAULT_CYCLES_PER_NODE * subnet_size, None);

    let balance_before = env.cycle_balance(canister_id);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wabt::wat2wasm(TEST_CANISTER).expect("invalid WAT"),
        vec![],
    )
    .unwrap();
    let balance_after = env.cycle_balance(canister_id);

    Cycles::from(balance_before - balance_after)
}

fn simulate_ingress_induction_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    // This function simulates `execute_round` to get the cost of ingress induction.
    // Filterred `CyclesAccountManagerConfig` is used to avoid irrelevant costs,
    // eg. execution cost.
    let env = StateMachineBuilder::new()
        .with_use_cost_scaling_flag(true)
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_config(Some(StateMachineConfig::new(
            filtered_subnet_config(subnet_type, KeepFeesFilter::IngressInductionCost),
            HypervisorConfig::default(),
        )))
        .build();
    let canister_id = env.create_canister_with_cycles(DEFAULT_CYCLES_PER_NODE * subnet_size, None);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wabt::wat2wasm(TEST_CANISTER).expect("invalid WAT"),
        vec![],
    )
    .unwrap();

    let balance_before = env.cycle_balance(canister_id);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let balance_after = env.cycle_balance(canister_id);

    Cycles::from(balance_before - balance_after)
}

fn trillion_cycles(value: f64) -> Cycles {
    let trillion = 1e12;
    Cycles::new((value * trillion) as u128)
}

fn get_cycles_account_manager_config(subnet_type: SubnetType) -> CyclesAccountManagerConfig {
    match subnet_type {
        SubnetType::System => CyclesAccountManagerConfig::system_subnet(),
        SubnetType::Application => CyclesAccountManagerConfig::application_subnet(),
        SubnetType::VerifiedApplication => {
            CyclesAccountManagerConfig::verified_application_subnet()
        }
    }
}

fn scale_cost(config: &CyclesAccountManagerConfig, cycles: Cycles, subnet_size: usize) -> Cycles {
    Cycles::from((cycles.get() * (subnet_size as u128)) / (config.reference_subnet_size as u128))
}

fn memory_cost(
    config: &CyclesAccountManagerConfig,
    bytes: NumBytes,
    duration: Duration,
    subnet_size: usize,
) -> Cycles {
    let one_gib = 1024 * 1024 * 1024;
    let use_cost_scaling = true;
    let cycles = Cycles::from(
        (bytes.get() as u128
            * config
                .gib_storage_per_second_fee(use_cost_scaling, subnet_size)
                .get()
            * duration.as_secs() as u128)
            / one_gib,
    );
    // No scaling below non-subsidised storage cost threshold.
    if subnet_size < CyclesAccountManagerConfig::fair_storage_cost_subnet_size() {
        cycles
    } else {
        scale_cost(config, cycles, subnet_size)
    }
}

fn compute_allocation_cost(
    config: &CyclesAccountManagerConfig,
    compute_allocation: ComputeAllocation,
    duration: Duration,
    subnet_size: usize,
) -> Cycles {
    let cycles = config.compute_percent_allocated_per_second_fee
        * duration.as_secs()
        * compute_allocation.as_percent();
    scale_cost(config, cycles, subnet_size)
}

fn calculate_one_gib_per_second_cost(
    config: &CyclesAccountManagerConfig,
    subnet_size: usize,
    compute_allocation: ComputeAllocation,
) -> Cycles {
    let one_gib = NumBytes::from(1 << 30);
    let duration = Duration::from_secs(1);
    memory_cost(config, one_gib, duration, subnet_size)
        + compute_allocation_cost(config, compute_allocation, duration, subnet_size)
}

// This function compares Cycles with absolute and relative tolerance.
//
// Simulated and calculated costs may carry calculation error, that has to be ignored in assertions.
// Eg. simulated cost may lose precision when is composed from several other integer costs (accumulated error).
fn is_almost_eq(a: Cycles, b: Cycles) -> bool {
    let a = a.get();
    let b = b.get();
    let mx = std::cmp::max(a, b);
    let rel_tolerance = mx / 1_000;
    let abs_tolerance = 1;
    let diff = a.abs_diff(b);

    diff <= abs_tolerance && diff <= rel_tolerance
}

fn convert_instructions_to_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
) -> Cycles {
    config.ten_update_instructions_execution_fee * (num_instructions.get() / 10)
}

fn prepay_execution_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
    subnet_size: usize,
) -> Cycles {
    scale_cost(
        config,
        config.update_message_execution_fee
            + convert_instructions_to_cycles(config, num_instructions),
        subnet_size,
    )
}

fn refund_unused_execution_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
    num_instructions_initially_charged: NumInstructions,
    prepaid_execution_cycles: Cycles,
    subnet_size: usize,
) -> Cycles {
    let num_instructions_to_refund =
        std::cmp::min(num_instructions, num_instructions_initially_charged);
    let cycles = convert_instructions_to_cycles(config, num_instructions_to_refund);

    scale_cost(config, cycles, subnet_size).min(prepaid_execution_cycles)
}

fn calculate_execution_cycles(
    config: &CyclesAccountManagerConfig,
    instructions: NumInstructions,
    subnet_size: usize,
) -> Cycles {
    let instructions_limit = NumInstructions::from(200_000_000_000);
    let instructions_left = instructions_limit - instructions;

    let prepaid_execution_cycles = prepay_execution_cycles(config, instructions_limit, subnet_size);
    let refund = refund_unused_execution_cycles(
        config,
        instructions_left,
        instructions_limit,
        prepaid_execution_cycles,
        subnet_size,
    );

    prepaid_execution_cycles - refund
}

fn ingress_induction_cost_from_bytes(
    config: &CyclesAccountManagerConfig,
    bytes: NumBytes,
    subnet_size: usize,
) -> Cycles {
    scale_cost(
        config,
        config.ingress_message_reception_fee + config.ingress_byte_reception_fee * bytes.get(),
        subnet_size,
    )
}

fn calculate_induction_cost(
    config: &CyclesAccountManagerConfig,
    ingress: &SignedIngressContent,
    subnet_size: usize,
) -> Cycles {
    let bytes_to_charge = ingress.arg().len()
        + ingress.method_name().len()
        + ingress.nonce().map(|n| n.len()).unwrap_or(0);

    ingress_induction_cost_from_bytes(config, NumBytes::from(bytes_to_charge as u64), subnet_size)
}

#[test]
fn test_subnet_size_one_gib_storage_default_cost() {
    let subnet_size_lo = 13;
    let subnet_size_hi = 34;
    let subnet_type = SubnetType::Application;
    let compute_allocation = ComputeAllocation::zero();
    let per_year: u64 = 60 * 60 * 24 * 365;

    // Assert small subnet size cost per year.
    let cost = simulate_one_gib_per_second_cost(subnet_type, subnet_size_lo, compute_allocation);
    assert_eq!(cost * per_year, trillion_cycles(4.005_072));

    // Assert big subnet size cost per year.
    let cost = simulate_one_gib_per_second_cost(subnet_type, subnet_size_hi, compute_allocation);
    assert_eq!(cost * per_year, trillion_cycles(4_652.792_300_736));

    // Assert big subnet size cost per year scaled to a small size.
    let adjusted_cost = (cost * subnet_size_lo) / subnet_size_hi;
    assert_eq!(adjusted_cost * per_year, trillion_cycles(1_779.008_800_464));
}

// Storage cost tests split into 2: zero and non-zero compute allocation.
// Reasons:
// - storage cost includes both memory cost and compute allocation cost
// - memory cost differs depending on subnet size
//   -  <20 nodes: memory cost is subsidised and does not scale
//   - >=20 nodes: memory cost is not-subsidised and scales according to subnet size
// - allocation cost always scales according to subnet size

#[test]
fn test_subnet_size_one_gib_storage_zero_compute_allocation() {
    let compute_allocation = ComputeAllocation::zero();
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size as usize;

    // Check default cost.
    assert_eq!(
        simulate_one_gib_per_second_cost(subnet_type, reference_subnet_size, compute_allocation),
        calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation)
    );

    // Below subnet size threshold: check if cost is the same.
    assert_eq!(
        simulate_one_gib_per_second_cost(subnet_type, 1, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 13, compute_allocation)
    );
    assert_eq!(
        simulate_one_gib_per_second_cost(subnet_type, 13, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 19, compute_allocation)
    );
    // Equal or above subnet size threshold: check if cost is increasing with subnet size.
    assert!(
        simulate_one_gib_per_second_cost(subnet_type, 31, compute_allocation)
            < simulate_one_gib_per_second_cost(subnet_type, 32, compute_allocation)
    );
    assert!(
        simulate_one_gib_per_second_cost(subnet_type, 101, compute_allocation)
            < simulate_one_gib_per_second_cost(subnet_type, 102, compute_allocation)
    );
    assert!(
        simulate_one_gib_per_second_cost(subnet_type, 1_001, compute_allocation)
            < simulate_one_gib_per_second_cost(subnet_type, 1_002, compute_allocation)
    );

    // Check with/without linear scaling.
    // Both lo/hi subnet sizes have to be a factor of reference_subnet_size from config
    // to avoid round errors.
    let reference_subnet_size_lo = config.reference_subnet_size as usize;
    let reference_subnet_size_hi = 2 * config.reference_subnet_size as usize;
    let subnet_size_threshold = CyclesAccountManagerConfig::fair_storage_cost_subnet_size();
    // Make sure subnet sizes comply to `lo < threshold <= hi`.
    assert!(reference_subnet_size_lo < subnet_size_threshold);
    assert!(subnet_size_threshold <= reference_subnet_size_hi);

    let reference_cost_lo =
        calculate_one_gib_per_second_cost(&config, reference_subnet_size_lo, compute_allocation);
    let reference_cost_hi =
        calculate_one_gib_per_second_cost(&config, reference_subnet_size_hi, compute_allocation);

    for subnet_size in 1..50 {
        let simulated_cost =
            simulate_one_gib_per_second_cost(subnet_type, subnet_size, compute_allocation);
        // Choose corresponding reference values according to a threshold value.
        let calculated_cost = if subnet_size < subnet_size_threshold {
            // No scaling, constant cost.
            reference_cost_lo
        } else {
            // Linear scaling.
            Cycles::new(
                reference_cost_hi.get() * subnet_size as u128 / reference_subnet_size_hi as u128,
            )
        };

        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "compute_allocation={:?}, subnet_size={}",
            compute_allocation,
            subnet_size
        );
    }
}

#[test]
fn test_subnet_size_one_gib_storage_non_zero_compute_allocation() {
    for compute_allocation in [
        ComputeAllocation::try_from(1).unwrap(),
        ComputeAllocation::try_from(50).unwrap(),
        ComputeAllocation::try_from(100).unwrap(),
    ] {
        let subnet_type = SubnetType::Application;
        let config = get_cycles_account_manager_config(subnet_type);
        let reference_subnet_size = config.reference_subnet_size as usize;

        // Check default cost.
        assert_eq!(
            simulate_one_gib_per_second_cost(
                subnet_type,
                reference_subnet_size,
                compute_allocation
            ),
            calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation)
        );

        // Check if cost is increasing with subnet size.
        assert!(
            simulate_one_gib_per_second_cost(subnet_type, 1, compute_allocation)
                < simulate_one_gib_per_second_cost(subnet_type, 2, compute_allocation)
        );
        assert!(
            simulate_one_gib_per_second_cost(subnet_type, 11, compute_allocation)
                < simulate_one_gib_per_second_cost(subnet_type, 12, compute_allocation)
        );
        assert!(
            simulate_one_gib_per_second_cost(subnet_type, 101, compute_allocation)
                < simulate_one_gib_per_second_cost(subnet_type, 102, compute_allocation)
        );
        assert!(
            simulate_one_gib_per_second_cost(subnet_type, 1_001, compute_allocation)
                < simulate_one_gib_per_second_cost(subnet_type, 1_002, compute_allocation)
        );

        // Check linear scaling.
        // Both lo/hi subnet sizes have to be a factor of reference_subnet_size from config
        // to avoid round errors.
        let reference_subnet_size_lo = config.reference_subnet_size as usize;
        let reference_subnet_size_hi = 2 * config.reference_subnet_size as usize;
        let subnet_size_threshold = CyclesAccountManagerConfig::fair_storage_cost_subnet_size();
        // Make sure subnet sizes comply to `lo < threshold <= hi`.
        assert!(reference_subnet_size_lo < subnet_size_threshold);
        assert!(subnet_size_threshold <= reference_subnet_size_hi);

        let reference_cost_base = calculate_one_gib_per_second_cost(
            &config,
            reference_subnet_size_lo,
            ComputeAllocation::zero(),
        );
        let reference_cost_lo = calculate_one_gib_per_second_cost(
            &config,
            reference_subnet_size_lo,
            compute_allocation,
        ) - reference_cost_base;
        let reference_cost_hi = calculate_one_gib_per_second_cost(
            &config,
            reference_subnet_size_hi,
            compute_allocation,
        );

        for subnet_size in 1..50 {
            let simulated_cost =
                simulate_one_gib_per_second_cost(subnet_type, subnet_size, compute_allocation);
            // Choose corresponding reference values according to a threshold value.
            let calculated_cost = if subnet_size < subnet_size_threshold {
                // Linear scaling with memory cost offset.
                reference_cost_base
                    + Cycles::new(
                        reference_cost_lo.get() * subnet_size as u128
                            / reference_subnet_size_lo as u128,
                    )
            } else {
                // Linear scaling.
                Cycles::new(
                    reference_cost_hi.get() * subnet_size as u128
                        / reference_subnet_size_hi as u128,
                )
            };

            assert!(
                is_almost_eq(simulated_cost, calculated_cost),
                "compute_allocation={:?}, subnet_size={}",
                compute_allocation,
                subnet_size
            );
        }
    }
}

#[test]
fn test_subnet_size_execute_install_code() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size as usize;
    let reference_cost = calculate_execution_cycles(
        &config,
        NumInstructions::from(TEST_CANISTER_INSTALL_EXECUTION_INSTRUCTIONS),
        reference_subnet_size,
    );

    // Check default cost.
    assert_eq!(
        simulate_execute_install_code_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert!(
        simulate_execute_install_code_cost(subnet_type, 1)
            < simulate_execute_install_code_cost(subnet_type, 2)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 11)
            < simulate_execute_install_code_cost(subnet_type, 12)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 101)
            < simulate_execute_install_code_cost(subnet_type, 102)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 1_001)
            < simulate_execute_install_code_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size as usize;
    let reference_cost = simulate_execute_install_code_cost(subnet_type, reference_subnet_size);
    for subnet_size in 1..50 {
        let simulated_cost = simulate_execute_install_code_cost(subnet_type, subnet_size);
        let calculated_cost =
            Cycles::new(reference_cost.get() * subnet_size as u128 / reference_subnet_size as u128);
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={}",
            subnet_size
        );
    }
}

#[test]
fn test_subnet_size_ingress_induction_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size as usize;
    let signed_ingress = SignedIngressBuilder::new()
        .method_name("inc")
        .nonce(3)
        .build();
    let reference_cost =
        calculate_induction_cost(&config, signed_ingress.content(), reference_subnet_size);

    // Check default cost.
    assert_eq!(
        simulate_ingress_induction_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert!(
        simulate_execute_install_code_cost(subnet_type, 1)
            < simulate_execute_install_code_cost(subnet_type, 2)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 11)
            < simulate_execute_install_code_cost(subnet_type, 12)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 101)
            < simulate_execute_install_code_cost(subnet_type, 102)
    );
    assert!(
        simulate_execute_install_code_cost(subnet_type, 1_001)
            < simulate_execute_install_code_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size as usize;
    let reference_cost = simulate_execute_install_code_cost(subnet_type, reference_subnet_size);
    for subnet_size in 1..50 {
        let simulated_cost = simulate_execute_install_code_cost(subnet_type, subnet_size);
        let calculated_cost =
            Cycles::new(reference_cost.get() * subnet_size as u128 / reference_subnet_size as u128);
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={}",
            subnet_size
        );
    }
}
