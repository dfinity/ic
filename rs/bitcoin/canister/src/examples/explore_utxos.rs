//! A script for exploring a UTXO set.
//!
//! Example run:
//!
//! cargo r --release --example explore-utxos -- --state-path ./bitcoin_mainnet
//!
//! >> balance <address>  # to get the balance of the given address.
//! >> utxos <address>  # to get the utxos of the given address.
use clap::Parser;
use ic_btc_canister::state::State;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    /// A path to load the state from.
    #[clap(long, parse(from_os_str), value_hint = clap::ValueHint::DirPath)]
    state_path: PathBuf,
}

fn main() {
    let args = Args::parse();

    print!("Loading state at {:?}... ", args.state_path.to_str());
    let state = State::load(&args.state_path).expect("Failed to load state");
    println!("Done.");

    loop {
        print!(">> ");
        let mut input = String::new();
        io::stdout().flush().unwrap();
        io::stdin()
            .read_line(&mut input)
            .expect("Error reading from STDIN");

        if input.contains("utxos") {
            let address_str = input.as_str().split(' ').collect::<Vec<&str>>()[1].trim();

            println!(
                "{:#?}",
                ic_btc_canister::store::get_utxos(&state, address_str, 0)
                    .unwrap()
                    .utxos
                    .into_iter()
                    .map(|x| (x.outpoint, x.value, x.height))
                    .collect::<Vec<_>>()
            );
        } else if input.contains("balance") {
            let address_str = input.as_str().split(' ').collect::<Vec<&str>>()[1].trim();

            println!(
                "{:#?}",
                ic_btc_canister::store::get_balance(&state, address_str, 0)
            );
        }
    }
}
