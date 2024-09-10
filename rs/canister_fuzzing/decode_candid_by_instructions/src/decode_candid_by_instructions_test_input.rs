use ic_state_machine_tests::StateMachineBuilder;
use ic_types::{ingress::WasmResult, Cycles};
use slog::Level;
use std::fs::File;
use std::io::Read;

fn read_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("FUZZ_CANISTER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn main() {
    let test = StateMachineBuilder::new()
        .no_dts()
        .with_log_level(Some(Level::Critical))
        .build();

    let canister_id = test
        .install_canister_with_cycles(
            read_canister_bytes(),
            vec![],
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();

    let bytes = include_bytes!(
        "/ic/rs/canister_fuzzing/decode_candid_by_instructions/crashes/adcd18db92297366"
    );

    let result = test.execute_ingress(canister_id, "decode", bytes.to_vec());

    let instructions = match result {
        Ok(WasmResult::Reply(result)) => {
            let mut cycles = [0u8; 8];
            cycles.clone_from_slice(&result[0..8]);
            u64::from_le_bytes(cycles)
        }
        Ok(WasmResult::Reject(message)) => {
            if message.contains("Canister trapped") {
                println!("{}", message);
            }
            0
        }
        _ => 0,
    };

    println!("Instructions used {}", instructions);
    println!("Input length {}", bytes.len());
    let threshold = instructions / bytes.len() as u64;
    println!(
        "Threshold crossed: {}, {}",
        threshold > 10_000_000,
        threshold
    );
}
