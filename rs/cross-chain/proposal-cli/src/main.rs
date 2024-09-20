mod candid;
mod canister;
mod dashboard;
mod git;
mod ic_admin;
mod proposal;

use crate::candid::encode_upgrade_args;
use crate::canister::TargetCanister;
use crate::dashboard::DashboardClient;
use crate::git::{GitCommitHash, GitRepository};
use crate::ic_admin::ProposalFiles;
use crate::proposal::{InstallProposalTemplate, ProposalTemplate, UpgradeProposalTemplate};
use clap::{Parser, Subcommand};
use ic_admin::IcAdminArgs;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A fictional versioning CLI
#[derive(Debug, Parser)] // requires `derive` feature
#[command(about = "CLI to make canister upgrade proposals", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// upgrade a canister
    #[command(arg_required_else_help = true)]
    Upgrade {
        /// The canister to upgrade
        canister: TargetCanister,

        /// The git commit hash of the currently deployed canister
        #[arg(long)]
        from: GitCommitHash,

        /// The git commit hash to which the canister should be upgraded
        #[arg(long)]
        to: GitCommitHash,

        /// Override default empty upgrade args.
        #[arg(long)]
        args: Option<String>,

        /// Output directory where generated files will be written
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Tool to submit proposal
        #[command(subcommand)]
        submit: Option<SubmitProposal>,
    },
    /// install a canister
    #[command(arg_required_else_help = true)]
    Install {
        /// The canister to install
        canister: TargetCanister,

        /// The git commit hash at which the canister should be installed
        #[arg(long)]
        at: GitCommitHash,

        /// Override default empty initialization args.
        #[arg(long)]
        args: Option<String>,

        /// Output directory where generated files will be written
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Tool to submit proposal
        #[command(subcommand)]
        submit: Option<SubmitProposal>,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum SubmitProposal {
    /// Generate the `ic-admin` command to submit the proposal.
    /// The proposal will *not* be automatically submitted.
    IcAdmin(IcAdminArgs),
}

impl SubmitProposal {
    fn render_command(self, proposal: &ProposalTemplate, generated_files: ProposalFiles) -> String {
        match self {
            SubmitProposal::IcAdmin(args) => {
                args.command_to_submit_proposal(proposal, generated_files)
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Upgrade {
            canister,
            from,
            to,
            args,
            output_dir,
            submit,
        } => {
            check_dir_has_required_permissions(&output_dir).expect("invalid output directory");

            let mut ic_repo = GitRepository::clone_ic();
            let dashboard = DashboardClient::new();
            let release_notes = ic_repo.release_notes(&canister, &from, &to);
            ic_repo.checkout(&to);
            let upgrade_args = encode_upgrade_args(
                &ic_repo.candid_file(&canister),
                args.unwrap_or(canister.default_upgrade_args()),
            );
            let canister_id = ic_repo.parse_canister_id(&canister);
            let last_upgrade_proposal_id = dashboard
                .list_canister_upgrade_proposals(&canister_id)
                .await
                .last()
                .cloned();
            let compressed_wasm_hash = ic_repo.build_canister_artifact(&canister);
            let output_dir = output_dir.join(canister.to_string()).join(to.to_string());

            let proposal = UpgradeProposalTemplate {
                canister: canister.clone(),
                to,
                compressed_wasm_hash,
                canister_id,
                last_upgrade_proposal_id,
                upgrade_args,
                release_notes,
            };

            write_to_disk(output_dir, proposal, submit, &ic_repo);
        }
        Commands::Install {
            canister,
            at,
            args,
            output_dir,
            submit,
        } => {
            let mut ic_repo = GitRepository::clone_ic();

            ic_repo.checkout(&at);
            let install_args = encode_upgrade_args(
                &ic_repo.candid_file(&canister),
                args.unwrap_or(canister.default_upgrade_args()),
            );
            let canister_id = ic_repo.parse_canister_id(&canister);
            let compressed_wasm_hash = ic_repo.build_canister_artifact(&canister);
            let output_dir = output_dir.join(canister.to_string()).join(at.to_string());

            let proposal = InstallProposalTemplate {
                canister,
                at,
                compressed_wasm_hash,
                canister_id,
                install_args,
            };

            write_to_disk(output_dir, proposal, submit, &ic_repo);
        }
    }
}

fn write_to_disk<P: Into<ProposalTemplate>>(
    output_dir: PathBuf,
    proposal: P,
    submit_with: Option<SubmitProposal>,
    ic_repo: &GitRepository,
) {
    const GOVERNANCE_PROPOSAL_SUMMARY_BYTES_MAX: usize = 30000;

    let mut errors = vec![];
    let proposal = proposal.into();
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .unwrap_or_else(|_| panic!("failed to remove {:?}", output_dir));
    }
    fs::create_dir_all(&output_dir).unwrap_or_else(|_| panic!("failed to create {:?}", output_dir));

    let bin_args_file_path = output_dir.join("args.bin");
    let mut args_file = fs::File::create(&bin_args_file_path)
        .unwrap_or_else(|_| panic!("failed to create {:?}", bin_args_file_path));
    proposal.write_bin_args(&mut args_file);
    println!(
        "Binary upgrade args written to '{}'",
        bin_args_file_path.display()
    );

    let hex_args_file_path = output_dir.join("args.hex");
    let mut args_file = fs::File::create(&hex_args_file_path)
        .unwrap_or_else(|_| panic!("failed to create {:?}", hex_args_file_path));
    proposal.write_hex_args(&mut args_file);
    println!(
        "Hexadecimal upgrade args written to '{}'",
        hex_args_file_path.display()
    );

    let artifact = output_dir.join(proposal.target_canister().artifact_file_name());
    ic_repo.copy_file(&proposal.target_canister().artifact(), &artifact);
    println!("Artifact written to '{}'", artifact.display());

    let proposal_summary_content = proposal.render();
    if proposal_summary_content.len() > GOVERNANCE_PROPOSAL_SUMMARY_BYTES_MAX {
        errors.push(format!(
            "Proposal summary is too long and will fail validation from the governance canister when submitted: {} bytes (max {})",
            proposal_summary_content.len(),
            GOVERNANCE_PROPOSAL_SUMMARY_BYTES_MAX
        ));
    }
    let proposal_summary = output_dir.join("summary.md");
    let mut summary_file = fs::File::create(&proposal_summary)
        .unwrap_or_else(|_| panic!("failed to create {:?}", proposal_summary));
    summary_file
        .write_all(proposal_summary_content.as_bytes())
        .unwrap();
    println!(
        "Proposal summary written to '{}'",
        proposal_summary.display()
    );

    if let Some(submit) = submit_with {
        use std::os::unix::fs::OpenOptionsExt;
        let proposal_files = ProposalFiles {
            wasm: artifact,
            arg: bin_args_file_path,
            summary: proposal_summary,
        }
        .strip_prefix(&output_dir)
        .unwrap();
        let command = submit.render_command(&proposal, proposal_files);
        let submit_script = output_dir.join("submit.sh");
        let mut submit_file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o740) //ensure script is executable
            .open(submit_script.as_path())
            .unwrap_or_else(|_| panic!("failed to create {:?}", submit_script));
        submit_file.write_all(command.as_bytes()).unwrap();
        println!("Submit script written to '{}'", submit_script.display());
    }

    if !errors.is_empty() {
        println!("Proposal was generated, but some errors were detected:");
        for error in errors {
            println!("  * {}", error);
        }
        panic!("errors detected");
    }
}

fn check_dir_has_required_permissions(output_dir: &Path) -> Result<(), String> {
    if !output_dir.exists() {
        return Err(format!(
            "Output directory does not exist: {}",
            output_dir.display()
        ));
    }
    let metadata = fs::metadata(output_dir).unwrap_or_else(|_| {
        panic!(
            "Failed to get metadata for output directory: {}",
            output_dir.display()
        )
    });
    if !metadata.is_dir() {
        return Err(format!(
            "Output directory should be a directory, not a file: {}",
            output_dir.display()
        ));
    }
    let permissions = metadata.permissions();
    if permissions.readonly() {
        return Err(format!(
            "Output directory should be writable: {}",
            output_dir.display()
        ));
    }
    Ok(())
}
