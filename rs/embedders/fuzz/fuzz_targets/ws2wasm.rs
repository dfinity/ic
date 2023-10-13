mod ic_wasm;
use arbitrary::{Arbitrary, Unstructured};
use clap::Parser;
use ic_wasm::ICWasmConfig;
use wasm_smith::ConfiguredModule;
use wasmprinter::print_bytes;

use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;

/// An utility binary to convert wasm-smith's Unstructured fuzzer input
/// into a strucutred wasm file.
#[derive(Parser)]
struct CommandLineArgs {
    /// The absolute path to the fuzzer testcase file.
    ws_path: PathBuf,

    /// Use WebAssembly textual representation (.wat)
    #[clap(long, action)]
    wat: bool,
}

fn main() -> io::Result<()> {
    let mut ws_path = CommandLineArgs::parse().ws_path;
    let f = File::open(ws_path.clone())?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    println!("Reading file at {}", ws_path.display());

    if buffer.len() < <ConfiguredModule<ICWasmConfig> as Arbitrary>::size_hint(0).0 {
        panic!("Not enough data to construct a valid wasm");
    }

    let unstrucutred = Unstructured::new(buffer.as_slice());
    let module = <ConfiguredModule<ICWasmConfig> as Arbitrary>::arbitrary_take_rest(unstrucutred)
        .expect("Unable to extract wasm from Unstructured data");
    let wasm = module.module.to_bytes();
    println!("WASM extraction successful!");

    let wat = CommandLineArgs::parse().wat;
    if wat {
        let wat_string = print_bytes(wasm).expect("couldn't translate WASM to wat");
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
        println!("WASM written to {}", ws_path.display());
    }
    Ok(())
}
