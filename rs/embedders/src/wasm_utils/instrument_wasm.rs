pub mod decoding;
pub mod errors;
pub mod instrumentation;
pub mod validation;
pub mod wasm_module_builder;

use decoding::decode_wasm;
use instrumentation::{instrument, InstructionCostTable, InstrumentationOutput};
use std::sync::Arc;
use validation::validate_wasm_binary;

use ic_config::embedders::Config as EmbeddersConfig;

fn usage() {
    println!(
        r#"
Usage: {} wasm_file

  Validate and instrument the wasm_file and output the result to the stdout."#,
        std::env::current_exe().unwrap().display()
    );
}

fn instrument_wasm(filename: &str) -> std::io::Result<()> {
    use std::io::Write;

    let contents = std::fs::read(filename)?;
    let decoded = decode_wasm(Arc::new(contents)).expect("failed to decode canister module");
    if let Err(err) = validate_wasm_binary(&decoded, &EmbeddersConfig::default()) {
        eprintln!("Failed to validate wasm file {}: {}", filename, err);
        std::process::exit(1);
    }
    match instrument(&decoded, &InstructionCostTable::default()) {
        Ok(InstrumentationOutput { binary, .. }) => std::io::stdout().write_all(binary.as_slice()),
        Err(err) => {
            eprintln!("Failed to instrument wasm file {}: {}", filename, err);
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let args_refs: Vec<_> = args.iter().map(|s| &s[..]).collect();
    match &args_refs[..] {
        ["--help"] | ["-h"] => {
            usage();
            std::process::exit(0);
        }
        [filename] => {
            if let Err(err) = instrument_wasm(filename) {
                eprintln!("Failed to read {}: {}", filename, err);
                std::process::exit(1);
            }
        }
        _ => {
            usage();
            eprint!("Expected a single argument, got: {:?}", args);
            std::process::exit(1);
        }
    }
}
