use candid::{Encode, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder, RejectResponse};
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
) -> Result<Vec<u8>, RejectResponse> {
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
    // testing for the exact number n of rounds could lead to flakiness
    // so we test for [n, n + 1] instead
    assert!(t1 >= t0 + Duration::from_nanos(dts_rounds));
    assert!(t1 <= t0 + Duration::from_nanos(dts_rounds + 1));

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
    let dts_rounds = 1; // DTS slice limit is very high on benchmarking subnets
    execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap();
}

#[test]
fn test_benchmarking_system_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_system_subnet()
        .build();

    let instructions = 42_000_000_000_u64;
    let dts_rounds = 1; // DTS slice limit is very high on benchmarking subnets
    execute_many_instructions(&pic, instructions, dts_rounds, true).unwrap();
}

#[test]
fn test_dts() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let instructions = 8_000_000_000_u64;
    let dts_rounds = instructions / 2_000_000_000;
    execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap();
}

#[test]
fn instruction_limit_exceeded() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let instructions = 42_000_000_000_u64;
    let dts_rounds = 20; // instruction limit exceeded after 20 rounds
    let res = execute_many_instructions(&pic, instructions, dts_rounds, false).unwrap_err();
    assert!(res.reject_message.contains(
        "Canister exceeded the limit of 40000000000 instructions for single message execution."
    ));
}
