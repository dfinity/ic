mod candid;
mod config;
mod types;
mod wasm;

use candid::CandidParser;
use clap::{arg, Parser};
use config::ConfigParser;
use std::collections::BTreeSet;
use std::path::PathBuf;
use types::CanisterEndpoint;
use wasm::WasmParser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the canister WASM file.
    #[arg(long)]
    wasm: PathBuf,
    /// Path to the canister Candid interface file.
    #[arg(long)]
    candid: PathBuf,
    /// Optionally specify hidden endpoints, i.e., endpoints that are exposed by the canister but
    /// not present in the Candid interface file.
    #[arg(long)]
    hidden: Vec<CanisterEndpoint>,
    /// Config file.
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config = ConfigParser::new(args.config, args.hidden).parse()?;

    let wasm_endpoints = WasmParser::new(args.wasm)
        .parse()
        .map_err(|e| format!("ERROR: Failed to parse WASM: {e}"))?;

    let candid_endpoints = CandidParser::new(args.candid)
        .parse()
        .map_err(|e| format!("ERROR: Failed to parse Candid file: {e}"))?;

    let missing_endpoints = candid_endpoints
        .difference(&wasm_endpoints)
        .collect::<BTreeSet<_>>();
    missing_endpoints.iter().for_each(|endpoint| {
        eprintln!(
            "ERROR: The following endpoint is missing from the WASM exports section: {endpoint}"
        );
    });

    let unexpected_endpoints = wasm_endpoints
        .iter()
        .filter(|endpoint| {
            !candid_endpoints.contains(endpoint) && !config.hidden().contains(endpoint)
        })
        .collect::<BTreeSet<_>>();
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
