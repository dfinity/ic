use std::sync::Arc;

use slog::Drain;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::{compile, decoding::decode_wasm},
    WasmtimeEmbedder,
};

fn usage() {
    println!(
        r#"
Usage: {} wasm_file

  Validate and instrument the wasm_file and output the result to the stdout."#,
        std::env::current_exe().unwrap().display()
    );
}

#[cfg(build = "debug")]
fn get_logger() -> slog::Logger {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!())
}
#[cfg(not(build = "debug"))]
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

fn instrument_wasm(filename: &str) -> std::io::Result<()> {
    use std::io::Write;

    let contents = std::fs::read(filename)?;
    let config = EmbeddersConfig::default();
    let decoded = decode_wasm(Arc::new(contents)).expect("failed to decode canister module");
    let embedder = WasmtimeEmbedder::new(config, get_logger().into());
    match compile(&embedder, &decoded) {
        Ok(output) => {
            std::io::stdout().write_all(output.1.instrumentation_output.binary.as_slice())
        }
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
