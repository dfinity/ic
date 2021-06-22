//! Binary crate for the command line interface (CLI) for the crypto component.
//!
//! The CLI is for demo/testing purposes and not for use in production!
use ic_crypto::cli;
use std::env;

/// Processes a command from the command line.
fn main() {
    let args: Vec<String> = env::args().collect();
    let result = cli::main(&args[1..]);
    if let Err((message, code)) = result {
        eprintln!("{}", message);
        std::process::exit(code);
    }
}
