use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, ValueEnum};
use slog::Drain;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::compile,
    wasm_utils::{decoding::decode_wasm, validate_and_instrument_for_testing},
};

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum Artifact {
    /// In instrumented Wasm module.
    InstrumentedWasm,
    /// An instrumented Wasm module that has been compiled to machine code by
    /// Wasmtime.
    WasmtimeModule,
    /// The full results of compilation as a bincode encoded
    /// `ic_embedders::SerializedModule`.
    SerializedModule,
}

impl From<Artifact> for clap::builder::OsStr {
    fn from(artifact: Artifact) -> clap::builder::OsStr {
        format!("{artifact:?}").into()
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Options {
    /// Input Wasm.
    input_file: PathBuf,

    /// Write output to the given file (defaul is stdout).
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    output_file: Option<PathBuf>,

    /// Artifact to produce.
    #[arg(value_enum, short, long, default_value = Artifact::InstrumentedWasm)]
    artifact: Artifact,
}

#[cfg(debug_assertions)]
fn get_logger() -> slog::Logger {
    use slog::slog_o;
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!())
}
#[cfg(not(debug_assertions))]
fn get_logger() -> slog::Logger {
    use slog::slog_o;

    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    slog::Logger::root(
        slog_term::FullFormat::new(plain)
            .build()
            .filter_level(slog::Level::Info)
            .fuse(),
        slog_o!(),
    )
}

fn process_wasm(filename: &Path, mut output_stream: Box<dyn std::io::Write>, artifact: Artifact) {
    let contents = std::fs::read(filename)
        .unwrap_or_else(|e| panic!("Failed to read input file {filename:?}: {e}"));
    let config = EmbeddersConfig::default();
    let decoded = decode_wasm(config.wasm_max_size, Arc::new(contents))
        .expect("failed to decode canister module");
    let embedder = WasmtimeEmbedder::new(config, get_logger().into());
    let result = match artifact {
        Artifact::InstrumentedWasm => {
            let (_validation, output) = validate_and_instrument_for_testing(&embedder, &decoded)
                .expect("Failed to instrument wasm file");
            output.binary.as_slice().to_vec()
        }
        Artifact::WasmtimeModule => {
            let (_, result) = compile(&embedder, &decoded);
            let (_, serialized_module) = result.expect("Error compiling Wasm");
            serialized_module.bytes.as_slice().to_vec()
        }
        Artifact::SerializedModule => {
            let (_, result) = compile(&embedder, &decoded);
            let (_, serialized_module) = result.expect("Error compiling Wasm");
            bincode::serialize(&serialized_module).expect("Failed to serialize module")
        }
    };
    output_stream
        .write_all(&result)
        .expect("Failed to write to output")
}

fn main() {
    let options = Options::parse();

    let output: Box<dyn std::io::Write> = if let Some(output_file) = options.output_file {
        Box::new(
            std::fs::File::create(&output_file)
                .unwrap_or_else(|e| panic!("Error opening output file {output_file:?}: {e}")),
        )
    } else {
        Box::new(std::io::stdout())
    };

    process_wasm(&options.input_file, output, options.artifact)
}
