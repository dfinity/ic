use ic_wasm_types::BinaryEncodedWasm;
use ic_wasm_utils::instrumentation::{instrument, InstructionCostTable, InstrumentationOutput};
use ic_wasm_utils::validation::{validate_wasm_binary, WasmValidationConfig};

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

    let contents = std::fs::read(filename).map(BinaryEncodedWasm::new)?;
    if let Err(err) = validate_wasm_binary(&contents, WasmValidationConfig::default()) {
        eprintln!("Failed to validate wasm file {}: {}", filename, err);
        std::process::exit(1);
    }
    match instrument(&contents, &InstructionCostTable::default()) {
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
