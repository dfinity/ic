use crate::download::download_signed_proposal;
use crate::proposal_build::validate_measurements;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use alternative_guestos::proposal::read_and_verify_signed_bless_alternative_guest_os_version_proposal;
use std::fs;
use std::path::PathBuf;

mod download;
mod proposal_build;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    DownloadSignedProposal {
        #[arg(long)]
        proposal_id: u64,
        #[arg(long, default_value = "https://ic0.app")]
        nns_url: String,
        #[arg(long)]
        output: PathBuf,
    },
    ValidateMeasurements {
        #[arg(long)]
        proposal_path: PathBuf,
        #[arg(long)]
        local_measurements_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::DownloadSignedProposal {
            proposal_id,
            nns_url,
            output,
        } => download_signed_proposal(proposal_id, &nns_url, &output).await,
        Command::ValidateMeasurements {
            proposal_path,
            local_measurements_path,
        } => {
            let proposal = read_and_verify_signed_bless_alternative_guest_os_version_proposal(
                &proposal_path,
                None,
            )?;
            let local_measurements =
                fs::read_to_string(&local_measurements_path).with_context(|| {
                    format!(
                        "Failed to read local measurements from {}",
                        local_measurements_path.display()
                    )
                })?;
            validate_measurements(&proposal, &local_measurements)
        }
    }
}
