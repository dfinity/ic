mod candid;
mod canister;
mod dashboard;
mod forum;
mod git;
mod ic_admin;
mod proposal;

use crate::canister::TargetCanister;
use crate::dashboard::DashboardClient;
use crate::forum::{CreateTopicRequest, DiscourseClient, ForumTopic};
use crate::git::{GitCommitHash, GitRepository};
use crate::ic_admin::ProposalFiles;
use crate::proposal::{InstallProposalTemplate, ProposalTemplate, UpgradeProposalTemplate};
use clap::{Parser, Subcommand};
use ic_admin::IcAdminArgs;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

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
        /// The canister(s) to upgrade
        canisters: Vec<TargetCanister>,

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
        /// The canister(s) to install
        canisters: Vec<TargetCanister>,

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
    /// Create a forum post for a new proposal
    #[command(arg_required_else_help = true)]
    CreateForumPost {
        /// ID of the proposals for which a forum topic should be created.
        proposal_ids: Vec<u64>,
        /// API key to submit the post
        #[arg(long)]
        api_key: String,
        /// Username associated with the API key
        #[arg(long)]
        api_user: String,
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
            canisters,
            from,
            to,
            args,
            output_dir,
            submit,
        } => {
            check_dir_has_required_permissions(&output_dir).expect("invalid output directory");
            let canister_per_git_repo = canisters_per_git_repo(canisters);
            for git_repo_url in canister_per_git_repo.keys() {
                let canisters: Vec<_> = canister_per_git_repo
                    .get(git_repo_url)
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect();
                let mut git_repo = GitRepository::clone(git_repo_url);
                let dashboard = DashboardClient::new();
                let release_notes = git_repo.release_notes_batch(&canisters, &from, &to);
                git_repo.checkout(&to);
                let upgrade_args: Vec<_> = git_repo.encode_args_batch(&canisters, args.clone());
                let canister_ids: Vec<_> =
                    canisters.iter().map(TargetCanister::canister_id).collect();
                let last_upgrade_proposal_ids: Vec<_> = dashboard
                    .list_canister_upgrade_proposals_batch(&canister_ids)
                    .await
                    .into_iter()
                    .map(|set| set.last().cloned())
                    .collect();
                let compressed_wasm_hashes = git_repo.build_canister_artifact_batch(&canisters);

                for (index, canister) in canisters.into_iter().enumerate() {
                    let output_dir = output_dir.join(canister.to_string()).join(to.to_string());

                    let proposal = UpgradeProposalTemplate {
                        canister: canister.clone(),
                        to: to.clone(),
                        compressed_wasm_hash: compressed_wasm_hashes[index].clone(),
                        canister_id: canister_ids[index],
                        last_upgrade_proposal_id: last_upgrade_proposal_ids[index],
                        upgrade_args: upgrade_args[index].clone(),
                        release_notes: release_notes[index].clone(),
                        build_artifact_command: canister.build_artifact_as_str(),
                    };

                    write_to_disk(output_dir, proposal, submit.clone(), &git_repo);
                }
            }
        }
        Commands::Install {
            canisters,
            at,
            args,
            output_dir,
            submit,
        } => {
            let canister_per_git_repo = canisters_per_git_repo(canisters);

            for git_repo_url in canister_per_git_repo.keys() {
                let canisters: Vec<_> = canister_per_git_repo
                    .get(git_repo_url)
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect();

                let mut git_repo = GitRepository::clone(git_repo_url);
                git_repo.checkout(&at);
                let install_args: Vec<_> = git_repo.encode_args_batch(&canisters, args.clone());
                let canister_ids: Vec<_> =
                    canisters.iter().map(TargetCanister::canister_id).collect();
                let compressed_wasm_hashes = git_repo.build_canister_artifact_batch(&canisters);

                for (index, canister) in canisters.into_iter().enumerate() {
                    let output_dir = output_dir.join(canister.to_string()).join(at.to_string());

                    let proposal = InstallProposalTemplate {
                        canister: canister.clone(),
                        at: at.clone(),
                        compressed_wasm_hash: compressed_wasm_hashes[index].clone(),
                        canister_id: canister_ids[index],
                        install_args: install_args[index].clone(),
                        build_artifact_command: canister.build_artifact_as_str(),
                    };

                    write_to_disk(output_dir, proposal, submit.clone(), &git_repo);
                }
            }
        }
        Commands::CreateForumPost {
            proposal_ids,
            api_key,
            api_user,
        } => {
            let dashboard = DashboardClient::new();
            let proposals = dashboard.retrieve_proposal_batch(&proposal_ids).await;
            let topic = ForumTopic::for_upgrade_proposals(proposals).unwrap_or_else(|e| {
                panic!("Failed to create forum topic for proposals {proposal_ids:?}: {e}")
            });
            let request = CreateTopicRequest::from(topic);
            println!("The following topic will be created");
            println!();
            println!("{request:?}");
            println!();
            println!("Are you sure? [y/N]");

            let mut confirm = String::new();
            io::stdin()
                .read_line(&mut confirm)
                .expect("Failed to read line");

            match confirm.trim() {
                "y" => {
                    const DFINITY_FORUM_URL: &str = "https://forum.dfinity.org";
                    let forum_client =
                        DiscourseClient::new(DFINITY_FORUM_URL.parse().unwrap(), api_user, api_key);
                    let response = forum_client
                        .create_topic(request)
                        .await
                        .expect("Failed to create topic");
                    println!(
                        "Forum post successfully created at {}{}",
                        DFINITY_FORUM_URL, response.post_url
                    );
                }
                _ => {
                    println!("Aborting, no forum topic created!")
                }
            }
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
            .unwrap_or_else(|_| panic!("failed to remove {output_dir:?}"));
    }
    fs::create_dir_all(&output_dir).unwrap_or_else(|_| panic!("failed to create {output_dir:?}"));

    let bin_args_file_path = output_dir.join("args.bin");
    let mut args_file = fs::File::create(&bin_args_file_path)
        .unwrap_or_else(|_| panic!("failed to create {bin_args_file_path:?}"));
    proposal.write_bin_args(&mut args_file);
    println!(
        "Binary upgrade args written to '{}'",
        bin_args_file_path.display()
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
        .unwrap_or_else(|_| panic!("failed to create {proposal_summary:?}"));
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
            .unwrap_or_else(|_| panic!("failed to create {submit_script:?}"));
        submit_file.write_all(command.as_bytes()).unwrap();
        println!("Submit script written to '{}'", submit_script.display());
    }

    if !errors.is_empty() {
        println!("Proposal was generated, but some errors were detected:");
        for error in errors {
            println!("  * {error}");
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

fn canisters_per_git_repo(
    canisters: Vec<TargetCanister>,
) -> BTreeMap<String, BTreeSet<TargetCanister>> {
    canisters
        .into_iter()
        .fold(BTreeMap::new(), |mut acc, canister| {
            let git_repo = canister.git_repository_url().to_string();
            acc.entry(git_repo).or_default().insert(canister);
            acc
        })
}
