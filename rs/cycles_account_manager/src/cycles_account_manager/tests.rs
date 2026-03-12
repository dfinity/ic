use super::*;
use candid::Encode;
use ic_management_canister_types_private::{CanisterSettingsArgsBuilder, UpdateSettingsArgs};
use ic_test_utilities_types::ids::subnet_test_id;

const WASM_EXECUTION_MODE: WasmExecutionMode = WasmExecutionMode::Wasm32;

fn create_cycles_account_manager(reference_subnet_size: usize) -> CyclesAccountManager {
    let mut config = CyclesAccountManagerConfig::application_subnet();
    config.reference_subnet_size = reference_subnet_size;

    CyclesAccountManager {
        max_num_instructions: NumInstructions::from(1_000_000_000),
        own_subnet_type: SubnetType::Application,
        own_subnet_id: subnet_test_id(0),
        config,
    }
}

#[test]
fn max_delayed_ingress_cost_payload_size_test() {
    let default_freezing_limit = 30 * 24 * 3600; // 30 days
    let payload = UpdateSettingsArgs {
        canister_id: CanisterId::from_u64(0).into(),
        settings: CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(default_freezing_limit)
            .build(),
        sender_canister_version: None, // ingress messages are not supposed to set this field
    };

    let payload_size = 2 * Encode!(&payload).unwrap().len();

    assert!(
        payload_size <= MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE,
        "Payload size: {payload_size}, is greater than MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE: {MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE}."
    );
}

#[test]
fn test_scale_cost() {
    let reference_subnet_size = 13;
    let cam = create_cycles_account_manager(reference_subnet_size);

    let cost = Cycles::new(13_000);
    assert_eq!(
        cam.scale_cost(cost, 0, CanisterCyclesCostSchedule::Normal),
        Cycles::new(0)
    );
    assert_eq!(
        cam.scale_cost(cost, 1, CanisterCyclesCostSchedule::Normal),
        Cycles::new(1_000)
    );
    assert_eq!(
        cam.scale_cost(cost, 6, CanisterCyclesCostSchedule::Normal),
        Cycles::new(6_000)
    );
    assert_eq!(
        cam.scale_cost(cost, 13, CanisterCyclesCostSchedule::Normal),
        Cycles::new(13_000)
    );
    assert_eq!(
        cam.scale_cost(cost, 26, CanisterCyclesCostSchedule::Normal),
        Cycles::new(26_000)
    );

    assert_eq!(
        cam.scale_cost(cost, 26, CanisterCyclesCostSchedule::Free),
        Cycles::new(0)
    );

    // Check overflow case.
    assert_eq!(
        cam.scale_cost(
            Cycles::new(u128::MAX),
            1_000_000,
            CanisterCyclesCostSchedule::Normal
        ),
        Cycles::new(u128::MAX) / reference_subnet_size
    );
}

#[test]
fn test_reference_subnet_size_is_not_zero() {
    // `reference_subnet_size` is used to scale cost according to a subnet size.
    // It should never be equal to zero.
    assert_ne!(
        CyclesAccountManagerConfig::application_subnet().reference_subnet_size,
        0
    );
    assert_ne!(
        CyclesAccountManagerConfig::verified_application_subnet().reference_subnet_size,
        0
    );
    assert_ne!(
        CyclesAccountManagerConfig::system_subnet().reference_subnet_size,
        0
    );
}

#[test]
fn http_requests_fee_scale() {
    let subnet_size: u64 = 34;
    let reference_subnet_size: u64 = 13;
    let request_size = NumBytes::from(17);
    let cycles_account_manager = create_cycles_account_manager(reference_subnet_size as usize);

    // Check the fee for a 13-node subnet.
    assert_eq!(
        cycles_account_manager.http_request_fee(
            request_size,
            None,
            reference_subnet_size as usize,
            CanisterCyclesCostSchedule::Normal,
        ),
        Cycles::from(1_603_786_800u64) * reference_subnet_size
    );

    // Check the fee for a 34-node subnet.
    assert_eq!(
        cycles_account_manager.http_request_fee(
            request_size,
            None,
            subnet_size as usize,
            CanisterCyclesCostSchedule::Normal,
        ),
        Cycles::from(1_605_046_800u64) * subnet_size
    );
}

#[test]
fn test_cycles_burn() {
    let subnet_size = 13;
    let cycles_account_manager = create_cycles_account_manager(subnet_size);
    let initial_balance = Cycles::new(1_000_000_000);
    let mut balance = initial_balance;
    let amount_to_burn = Cycles::new(1_000_000);

    assert_eq!(
        cycles_account_manager.cycles_burn(
            &mut balance,
            amount_to_burn,
            NumSeconds::new(0),
            MemoryAllocation::default(),
            0.into(),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            13,
            CanisterCyclesCostSchedule::Normal,
            Cycles::new(0)
        ),
        amount_to_burn
    );

    // Check that the balance is updated properly.
    assert_eq!(balance + amount_to_burn, initial_balance);

    assert_eq!(
        cycles_account_manager.cycles_burn(
            &mut balance,
            amount_to_burn,
            NumSeconds::new(0),
            MemoryAllocation::default(),
            0.into(),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            13,
            CanisterCyclesCostSchedule::Free,
            Cycles::new(0)
        ),
        amount_to_burn
    );

    // Check that the balance is updated properly.
    assert_eq!(balance + amount_to_burn + amount_to_burn, initial_balance)
}

#[test]
fn test_convert_instructions_to_cycles() {
    let subnet_size = 13;
    let cycles_account_manager = create_cycles_account_manager(subnet_size);

    // Everything up to `u128::MAX / 4` should be converted as normal:
    // `(ten_update_instructions_execution_fee * num_instructions) / 10`

    // `(10 * 0) / 10 == 0`
    assert_eq!(
        cycles_account_manager.convert_instructions_to_cycles(0.into(), WASM_EXECUTION_MODE),
        0_u64.into()
    );

    // `(10 * 9) / 10 == 9`
    assert_eq!(
        cycles_account_manager.convert_instructions_to_cycles(9.into(), WASM_EXECUTION_MODE),
        ((10 * 9_u64) / 10).into()
    );

    // As the maximum number of instructions is bounded by its type, i.e. `u64::MAX`,
    // the normal conversion is applied for the whole instructions range.
    // `convert_instructions_to_cycles(u64::MAX) == (10 * u64::MAX) / 10`
    let u64_max_cycles =
        cycles_account_manager.convert_instructions_to_cycles(u64::MAX.into(), WASM_EXECUTION_MODE);
    assert_eq!(u64_max_cycles, ((10 * u128::from(u64::MAX)) / 10).into());
    // `convert_instructions_to_cycles(u64::MAX) != 10 * (u64::MAX / 10)`
    assert_ne!(u64_max_cycles, (10 * (u128::from(u64::MAX) / 10)).into());
}
