//! The main function of the cup-signer
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct CupSignerArgs {
    /// The path to the CUP
    #[clap(long)]
    pub cup_path: PathBuf,

    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
pub enum SubCommand {
    /// Sign a CUP
    Sign(SignArgs),
    /// Verify a signature
    Verify(VerifyArgs),
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct SignArgs {
    /// The path to the CUP
    #[clap(long)]
    pub priv_key_path: PathBuf,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct VerifyArgs {
    /// The path to the CUP
    #[clap(long)]
    pub pub_key_path: PathBuf,

    #[clap(long)]
    pub local_store_path: PathBuf,
}

fn main() {
    let args = CupSignerArgs::parse();
    let cup_bytes = fs::read(&args.cup_path).expect("Failed to read file");

    match args.subcmd {
        SubCommand::Sign(args) => sign(&cup_bytes, args.priv_key_path),
        SubCommand::Verify(args) => verify(&cup_bytes, args.pub_key_path, args.local_store_path),
    }
}

fn sign(cup_bytes: &[u8], priv_key_path: PathBuf) {
    println!("Sign: {:?}, {}", cup_bytes, priv_key_path.display())
}

fn verify(cup_bytes: &[u8], pub_key_path: PathBuf, local_store_path: PathBuf) {
    println!(
        "Verify: {:?}, {}, {}",
        cup_bytes,
        pub_key_path.display(),
        local_store_path.display(),
    )
}
