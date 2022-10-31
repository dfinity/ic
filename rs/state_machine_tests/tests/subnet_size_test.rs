use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{CanisterSettingsArgs, StateMachineBuilder};
use ic_types::{ComputeAllocation, Cycles, NumBytes};
use std::time::Duration;

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
        Cycles::new(1_000_000_000) * subnet_size,
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
