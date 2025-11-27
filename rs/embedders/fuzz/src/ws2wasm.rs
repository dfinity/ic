use arbitrary::{Arbitrary, Unstructured};
use clap::Parser;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_logger::replica_logger::no_op_logger;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use wasm_fuzzers::ic_wasm::ICWasmModule;
use wasmprinter::print_bytes;

use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::{decoding::decode_wasm, validate_and_instrument_for_testing},
};

/// An utility binary to convert wasm-smith's Unstructured fuzzer input
/// into a strucutred wasm file.
#[derive(Parser)]
struct CommandLineArgs {
    /// The absolute path to the fuzzer testcase file.
    ws_path: PathBuf,

    /// Validate and Instrument the wasm
    #[clap(short, long, action)]
    inst: bool,

    /// Use WebAssembly textual representation (.wat)
    #[clap(short, long, action)]
    wat: bool,

    /// print WAT to stdout
    #[clap(short, long, action)]
    print: bool,
}

fn main() -> io::Result<()> {
    let mut ws_path = CommandLineArgs::parse().ws_path;
    let f = File::open(ws_path.clone())?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    println!("Reading file at {}", ws_path.display());

    if buffer.len() < <ICWasmModule as Arbitrary>::size_hint(0).0 {
        panic!("Not enough data to construct a valid wasm");
    }

    let unstrucutred = Unstructured::new(buffer.as_slice());
    let module = <ICWasmModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
        .expect("Unable to extract wasm from Unstructured data");
    let mut wasm = module.module.to_bytes();
    println!("Wasm extraction successful!");

    let instrumentation = CommandLineArgs::parse().inst;
    if instrumentation {
        let config = EmbeddersConfig::default();
        let decoded = decode_wasm(config.wasm_max_size, Arc::new(wasm))
            .expect("failed to decode canister module");
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());
        match validate_and_instrument_for_testing(&embedder, &decoded) {
            Ok((_, output)) => {
                wasm = output.binary.as_slice().to_vec();
            }
            Err(err) => {
                println!(
                    "Failed to instrument wasm file {}: {}",
                    ws_path.display(),
                    err
                );
                std::process::exit(1);
            }
        }
    }

    let wat = CommandLineArgs::parse().wat;
    let print = CommandLineArgs::parse().print;
    if wat || print {
        let wat_string = print_bytes(wasm).expect("couldn't translate Wasm to wat");

        if print {
            println!("{}", wat_string);
            return Ok(());
        }

        // reset output file_name to file_name.wat
        let file_name = format!(
            "{}.wat",
            ws_path
                .file_name()
                .expect("Unable to get file_name")
                .to_string_lossy()
        );
        ws_path.set_file_name(file_name);

        let mut file = File::create(ws_path.clone())?;
        file.write_all(wat_string.as_bytes())?;
        println!("WAT written to {}", ws_path.display());
    } else {
        // reset output file_name to file_name.wasm
        let file_name = format!(
            "{}.wasm",
            ws_path
                .file_name()
                .expect("Unable to get file_name")
                .to_string_lossy()
        );
        ws_path.set_file_name(file_name);

        let mut file = File::create(ws_path.clone())?;
        file.write_all(wasm.as_slice())?;
        println!("Wasm written to {}", ws_path.display());
    }
    Ok(())
}
