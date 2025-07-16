mod candid;
mod wasm;

use candid::CandidParser;
use canscan::CanisterEndpoint;
use clap::{arg, Parser};
use std::path::PathBuf;
use wasm::WasmParser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the canister WASM file
    #[arg(long)]
    wasm: PathBuf,
    /// Path to the canister Candid interface file
    #[arg(long)]
    candid: PathBuf,
    /// Whitelist of allowed hidden methods
    #[arg(long)]
    hidden: Vec<CanisterEndpoint>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let wasm_endpoints = WasmParser::new(args.wasm)
        .parse()
        .map_err(|e| format!("ERROR: Failed to parse WASM: {e}"))?;

    let candid_endpoints = CandidParser::new(args.candid)
        .parse()
        .map_err(|e| format!("ERROR: Failed to parse Candid file: {e}"))?;

    let missing_endpoints = candid_endpoints.difference(&wasm_endpoints);
    missing_endpoints.iter().for_each(|endpoint| {
        eprintln!(
            "ERROR: The following endpoint is missing from the WASM exports section: {endpoint}"
        );
    });

    let unexpected_endpoints = wasm_endpoints
        .difference(&candid_endpoints)
        .into_iter()
        .filter(|endpoint| !args.hidden.contains(endpoint))
        .collect::<Vec<_>>();
    unexpected_endpoints.iter().for_each(|endpoint| {
        eprintln!(
            "ERROR: The following endpoint is unexpected in the WASM exports section: {endpoint}"
        );
    });

    if !missing_endpoints.is_empty() || !unexpected_endpoints.is_empty() {
        Err("Canister WASM and Candid interface do not match".into())
    } else {
        println!("Canister WASM and Candid interface match!");
        Ok(())
    }
}
