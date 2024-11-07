use candid::{Encode, Principal};
use pocket_ic::{common::rest::DtsFlag, PocketIc, PocketIcBuilder, UserError, WasmResult};
use std::time::Duration;

// 200T cycles
const INIT_CYCLES: u128 = 200_000_000_000_000;

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

fn execute_many_instructions(
    pic: &PocketIc,
    instructions: u64,
    dts_rounds: u64,
    system_subnet: bool,
) -> Result<WasmResult, UserError> {
    // Create a canister.
    let t0 = pic.get_time();
    let can_id = pic.create_canister();
    let t1 = pic.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Charge the canister with 200T cycles.
    pic.add_cycles(can_id, INIT_CYCLES);

    let initial_cycles = pic.cycle_balance(can_id);
    assert_eq!(initial_cycles, INIT_CYCLES);

    // Install the test canister wasm on the canister.
    pic.install_canister(can_id, test_canister_wasm(), vec![], None);

    let t0 = pic.get_time();
    let res = pic.update_call(
        can_id,
        Principal::anonymous(),
        "execute_many_instructions",
        Encode!(&instructions).unwrap(),
    );
    let t1 = pic.get_time();
    assert!(t1 >= t0 + Duration::from_nanos(dts_rounds));

    if system_subnet {
        let cycles = pic.cycle_balance(can_id);
        assert_eq!(cycles, initial_cycles);
    }

    res
}

#[test]
fn test_benchmarking_app_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_application_subnet()
        .build();

    let instructions = 42_000_000_000_u64;
    let dts_rounds = 1; // DTS is disabled on benchmarking subnets
    execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap();
}

#[test]
fn test_benchmarking_system_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_system_subnet()
        .build();

    let instructions = 42_000_000_000_u64;
    let dts_rounds = 1; // DTS is disabled on benchmarking subnets
    execute_many_instructions(&pic, instructions, dts_rounds, true).unwrap();
}

fn test_dts(dts_flag: DtsFlag) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_dts_flag(dts_flag)
        .build();

    let instructions = 4_000_000_000_u64;
    let dts_rounds = if let DtsFlag::Enabled = dts_flag {
        instructions / 2_000_000_000
    } else {
        1
    };
    execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap();
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

    let instructions = 42_000_000_000_u64;
    let dts_rounds = if let DtsFlag::Enabled = dts_flag {
        20 // instruction limit exceeded after 20 rounds
    } else {
        1
    };
    let res = execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap_err();
    assert!(res.description.contains(
        "Canister exceeded the limit of 40000000000 instructions for single message execution."
    ));
}

#[test]
fn test_instruction_limit_exceeded_dts_enabled() {
    instruction_limit_exceeded(DtsFlag::Enabled);
}

#[test]
fn test_instruction_limit_exceeded_dts_disabled() {
    instruction_limit_exceeded(DtsFlag::Disabled);
}
