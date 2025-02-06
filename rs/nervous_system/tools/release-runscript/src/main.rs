mod utils;
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use url::Url;
use utils::*;

#[derive(Debug, Parser)]
struct DetermineTargets {
    #[arg(long)]
    commit: String,
}

#[derive(Debug, Parser)]
struct RunTests {
    #[arg(long)]
    commit: String,
    #[arg(long, num_args = 0..,)]
    nns_canisters: Vec<String>,
    #[arg(long, num_args = 0..,)]
    sns_canisters: Vec<String>,
}

#[derive(Debug, Parser)]
struct CreateProposalTexts {
    #[arg(long)]
    commit: String,
    #[arg(long, num_args = 0..,)]
    nns_canisters: Vec<String>,
    #[arg(long, num_args = 0..,)]
    sns_canisters: Vec<String>,
}

#[derive(Debug, Parser)]
struct SubmitProposals {
    #[arg(long, num_args = 0..,)]
    nns_proposal_text_paths: Vec<PathBuf>,
    #[arg(long, num_args = 0..,)]
    sns_proposal_text_paths: Vec<PathBuf>,
}

#[derive(Debug, Parser)]
struct CreateForumPost {
    #[arg(long, num_args = 0..,)]
    nns_proposal_text_paths: Vec<PathBuf>,
    #[arg(long, num_args = 0..,)]
    nns_proposal_ids: Vec<String>,
    #[arg(long, num_args = 0..,)]
    sns_proposal_text_paths: Vec<PathBuf>,
    #[arg(long, num_args = 0..,)]
    sns_proposal_ids: Vec<String>,
}
#[derive(Debug, Parser)]
struct ScheduleVote {
    #[arg(long, num_args = 0..,)]
    nns_proposal_ids: Vec<String>,
    #[arg(long, num_args = 0..,)]
    sns_proposal_ids: Vec<String>,
}

#[derive(Debug, Parser)]
struct UpdateChangelog;

#[derive(Debug, Subcommand)]
enum Step {
    #[command(about = "Step 1: Pick Release Candidate Commit")]
    PickReleaseCandidateCommit,
    #[command(about = "Step 2: Determine Upgrade Targets")]
    DetermineTargets(DetermineTargets),
    #[command(about = "Step 3: Run NNS Upgrade Tests")]
    RunTests(RunTests),
    #[command(about = "Step 4: Create Proposal Texts")]
    CreateProposalTexts(CreateProposalTexts),
    #[command(about = "Step 5: Submit Proposals")]
    SubmitProposals(SubmitProposals),
    #[command(about = "Step 6: Create Forum Post")]
    CreateForumPost(CreateForumPost),
    #[command(about = "Step 7: Schedule Trusted Neurons Vote")]
    ScheduleVote(ScheduleVote),
    #[command(about = "Step 8: Update Changelog")]
    UpdateChangelog(UpdateChangelog),
}

#[derive(Debug, Parser)]
#[clap(
    name = "release-runscript",
    about = "Release NNS and SNS canisters.",
    version
)]
struct ReleaseRunscript {
    #[command(subcommand)]
    step: Option<Step>,
}

fn main() -> Result<()> {
    let args = match ReleaseRunscript::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            bail!("{}", e);
        }
    };

    print_header();

    match args.step {
        None | Some(Step::PickReleaseCandidateCommit) => run_pick_commit(),
        Some(Step::DetermineTargets(cmd)) => run_determine_targets(cmd),
        Some(Step::RunTests(cmd)) => run_run_tests(cmd),
        Some(Step::CreateProposalTexts(cmd)) => run_create_proposal_texts(cmd),
        Some(Step::SubmitProposals(cmd)) => run_submit_proposals(cmd),
        Some(Step::CreateForumPost(cmd)) => run_create_forum_post(cmd),
        Some(Step::ScheduleVote(cmd)) => run_schedule_vote(cmd),
        Some(Step::UpdateChangelog(cmd)) => run_update_changelog(cmd),
    }
}

fn run_pick_commit() -> Result<()> {
    // Get the ic directory.
    let ic = ic_dir();

    // Build the absolute path to the cmd.sh script.
    let cmd_path = ic.join("testnet/tools/nns-tools/cmd.sh");

    // Run the command with the required argument.
    let output = Command::new(cmd_path)
        .arg("latest_commit_with_prebuilt_artifacts")
        .current_dir(&ic)
        .output()?;

    let commit = if output.status.success() {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("A commit with prebuilt artifacts was found with the following command: `./testnet/tools/nns-tools/cmd.sh latest_commit_with_prebuilt_artifacts`.");
        input_with_default("Commit to release", &commit)?
    } else {
        println!(
            "Automatically determining the commit hash failed with error:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // get input from user for the commit
        input("Enter the commit hash, which you can find by running `./testnet/tools/nns-tools/cmd.sh latest_commit_with_prebuilt_artifacts`")?
    };

    print_step(
        1,
        "Pick Release Candidate Commit",
        &format!("Chosen commit: {}", commit),
    )?;

    // Continue to next step.
    run_determine_targets(DetermineTargets { commit })
}

fn run_determine_targets(cmd: DetermineTargets) -> Result<()> {
    let DetermineTargets { commit } = cmd;
    println!("Now choose which canisters to upgrade. You can run ./testnet/tools/nns-tools/list-new-commits.sh to see the changes for each canister.");

    // Define the candidate canisters.
    let nns_candidates = [
        "Governance",
        "Root",
        "SNS-Wasm",
        "Lifeline",
        "Registry",
        "Cycles-Minting",
        "Genesis-Token",
    ];
    let sns_candidates = ["Root", "Governance", "Swap", "Ledger", "Archive", "Index"];

    // Prepare vectors for selected releases.
    let mut nns_canisters: Vec<String> = Vec::new();
    let mut sns_canisters: Vec<String> = Vec::new();

    // Ask about NNS canisters.
    println!("NNS canisters:");
    for &canister in nns_candidates.iter() {
        if input_yes_or_no(&format!("   Release {}?", canister), false)? {
            nns_canisters.push(canister.to_string().to_lowercase());
        }
    }

    // Ask about SNS canisters.
    println!("SNS canisters:");
    for &canister in sns_candidates.iter() {
        if input_yes_or_no(&format!("   Release {}?", canister), false)? {
            sns_canisters.push(canister.to_string().to_lowercase());
        }
    }

    print_step(
        2,
        "Determine Upgrade Targets",
        &format!(
            "NNS canisters selected for release: {}\nSNS canisters selected for release: {}",
            nns_canisters.join(", "),
            sns_canisters.join(", ")
        ),
    )?;

    run_run_tests(RunTests {
        commit,
        nns_canisters,
        sns_canisters,
    })
}

fn run_run_tests(cmd: RunTests) -> Result<()> {
    let RunTests {
        commit,
        nns_canisters,
        sns_canisters,
    } = cmd;
    print_step(3,
        "Run NNS Upgrade Tests",
        "Verify the commit you chose at the previous step has a green check on this page: https://github.com/dfinity/ic/actions/workflows/ci-main.yml?query=branch:master+event:push+is:success

If not, you can also run the upgrade tests manually:
    - Follow instructions in: testnet/tools/nns-tools/README.md#upgrade-testing-via-bazel
   
2. SNS Testing Note:
   - No manual testing needed for SNS
   - Covered by sns_release_qualification in CI
   - Example: Test at rs/nervous_system/integration_tests/tests/sns_release_qualification.rs",
    )?;

    run_create_proposal_texts(CreateProposalTexts {
        commit,
        nns_canisters,
        sns_canisters,
    })
}

fn run_create_proposal_texts(cmd: CreateProposalTexts) -> Result<()> {
    let CreateProposalTexts {
        commit,
        nns_canisters,
        sns_canisters,
    } = cmd;

    // Create proposals directory under ic_dir/proposals/release-{ISO_DATE}
    let ic = ic_dir();
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let proposals_dir = ic
        .join("..")
        .join("proposals")
        .join(format!("release-{}", today));

    // ensure the directory is empty
    // check if the directory exists
    if proposals_dir.exists() {
        println!("Removing existing proposals/ directory");
        std::fs::remove_dir_all(&proposals_dir)?;
    }
    std::fs::create_dir_all(&proposals_dir).expect("Failed to create proposals directory");

    let proposals_dir = proposals_dir.canonicalize()?;

    println!(
        "Creating proposal texts for {} NNS canisters and {} SNS canisters at commit {}",
        nns_canisters.len(),
        sns_canisters.len(),
        commit
    );

    let mut nns_proposal_text_paths = Vec::new();
    let mut sns_proposal_text_paths = Vec::new();

    // For each NNS canister, run the prepare-nns-upgrade-proposal-text.sh script and write its output to a file.
    for canister in &nns_canisters {
        println!("Creating proposal text for NNS canister: {}", canister);
        let script = ic.join("testnet/tools/nns-tools/prepare-nns-upgrade-proposal-text.sh");
        // cycles minting requires an upgrade arg, usually '()'
        let output = if canister != "cycles-minting" {
            Command::new(script)
                .arg(canister)
                .arg(&commit)
                .current_dir(&ic)
                .output()
                .expect("Failed to run NNS proposal text script")
        } else {
            let upgrade_arg = input_with_default("Upgrade arg for CMC?", "'()'")?;
            Command::new(script)
                .arg(canister)
                .arg(&commit)
                .arg(upgrade_arg)
                .current_dir(&ic)
                .output()
                .expect("Failed to run NNS proposal text script")
        };
        if !output.status.success() {
            bail!(
                "Failed to create proposal text for NNS canister {} due to error: stdout: {}, stderr: {}",
                canister,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let file_path = proposals_dir.join(format!("nns-{}.md", canister));
        std::fs::write(&file_path, output.stdout).expect("Failed to write NNS proposal file");
        nns_proposal_text_paths.push(file_path);
    }

    // For each SNS canister, run the prepare-publish-sns-wasm-proposal-text.sh script.
    for canister in &sns_canisters {
        println!("Creating proposal text for SNS canister: {}", canister);
        let script = ic.join("testnet/tools/nns-tools/prepare-publish-sns-wasm-proposal-text.sh");
        // The SNS script is expected to write directly to the file provided as an argument.
        let file_path = proposals_dir.join(format!("sns-{}.md", canister));
        let file_path_str = file_path.to_str().expect("Invalid file path");
        let output = Command::new(script)
            .arg(canister)
            .arg(&commit)
            .arg(file_path_str)
            .current_dir(&ic)
            .output()
            .expect("Failed to run SNS proposal text script");
        if !output.status.success() {
            bail!(
                "Failed to create proposal text for SNS canister {} due to error: {}",
                canister,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        sns_proposal_text_paths.push(file_path);
    }

    for proposal_text_path in &nns_proposal_text_paths {
        println!(
            "Viewing NNS proposal with vscode: {}",
            proposal_text_path.display()
        );
        let mut cmd = Command::new("code");
        cmd.arg(proposal_text_path);
        cmd.current_dir(&ic);
        cmd.output()
            .expect("Failed to view NNS proposal with vscode");
    }

    for proposal_text_path in &sns_proposal_text_paths {
        println!(
            "Viewing SNS proposal with vscode: {}",
            proposal_text_path.display()
        );
        let mut cmd = Command::new("code");
        cmd.arg(proposal_text_path);
        cmd.current_dir(&ic);
        cmd.output()
            .expect("Failed to view SNS proposal with vscode");
    }

    use std::fmt::Write;
    print_step(
        4,
        "Create Proposal Texts",
        &format!("I created proposal texts for each canister to be upgraded in the following directory: {}.
NNS proposal texts: {}
SNS proposal texts: {}",
            proposals_dir.display(),
            nns_proposal_text_paths.iter().fold(String::new(), |mut acc, path| {
                let _ = write!(acc, "\n  - {}", path.display());
                acc
            }),
            sns_proposal_text_paths.iter().fold(String::new(), |mut acc, path| {
                let _ = write!(acc, "\n  - {}", path.display());
                acc
            })
        )
    )?;

    run_submit_proposals(SubmitProposals {
        nns_proposal_text_paths,
        sns_proposal_text_paths,
    })
}

fn run_submit_proposals(cmd: SubmitProposals) -> Result<()> {
    let SubmitProposals {
        nns_proposal_text_paths,
        sns_proposal_text_paths,
    } = cmd;

    if !input_yes_or_no("Do you want to submit upgrade proposals?", false)? {
        println!("Skipping upgrade proposal submission and all following steps.");
        return Ok(());
    }
    println!();

    // Ask the user for the SUBMITTING_NEURON_ID (example: 51)
    println!("We are now going to submit the proposals. For this step, we need your neuron ID. If you are submitting on behalf of DFINITY, your neuron ID is written at this notion page: <https://www.notion.so/dfinityorg/3a1856c603704d51a6fcd2a57c98f92f?v=fc597afede904e499744f3528cad6682>.");
    let neuron_id = input("Enter your neuron ID (e.g. 51)")?;

    println!("Plug in your HSM key. Unplug your Ubikey.");
    println!("Once you have done that, you can test your key hardware with the following command:");
    println!("    pkcs11-tool --list-slots");
    println!("And you can practice entering your password with: ");
    println!("    pkcs11-tool --login --test");
    press_enter_to_continue()?;

    let ic = ic_dir();

    let mut sns_proposal_ids = Vec::new();
    let mut nns_proposal_ids = Vec::new();

    // For each NNS proposal, run the submission script.
    for proposal_path in &nns_proposal_text_paths {
        println!("Submitting NNS proposal: {}", proposal_path.display());
        let script = ic.join("testnet/tools/nns-tools/submit-mainnet-nns-upgrade-proposal.sh");
        let output = Command::new(script)
            .arg(proposal_path.to_str().expect("Invalid proposal path"))
            .arg(&neuron_id)
            .current_dir(&ic)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("Failed to run submit-mainnet-nns-upgrade-proposal.sh");
        if !output.status.success() {
            bail!(
                "Submission failed for {}: {}",
                proposal_path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!("Submission successful for {}", proposal_path.display());
        nns_proposal_ids.push(input("Enter the proposal ID")?);
    }

    // For each SNS proposal, run the submission script.
    for proposal_path in &sns_proposal_text_paths {
        println!("Submitting SNS proposal: {}", proposal_path.display());
        let script = ic.join("testnet/tools/nns-tools/submit-mainnet-publish-sns-wasm-proposal.sh");
        let output = Command::new(script)
            .arg(proposal_path.to_str().expect("Invalid proposal path"))
            .arg(&neuron_id)
            .current_dir(&ic)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("Failed to run submit-mainnet-publish-sns-wasm-proposal.sh");
        if !output.status.success() {
            bail!(
                "Submission failed for {}: {}",
                proposal_path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!("Submission successful for {}", proposal_path.display());
        sns_proposal_ids.push(input("Enter the proposal ID")?);
    }

    use std::fmt::Write;
    print_step(
        5,
        "Submit Proposals",
        &format!(
            "I submitted the following proposals: 
            NNS: {}
            SNS: {}",
            nns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
                let _ = write!(
                    acc,
                    "\n  - https://dashboard.internetcomputer.org/proposal/{}",
                    id
                );
                acc
            }),
            sns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
                let _ = write!(
                    acc,
                    "\n  - https://dashboard.internetcomputer.org/proposal/{}",
                    id
                );
                acc
            })
        ),
    )?;

    run_create_forum_post(CreateForumPost {
        nns_proposal_text_paths,
        nns_proposal_ids,
        sns_proposal_text_paths,
        sns_proposal_ids,
    })
}

fn run_create_forum_post(cmd: CreateForumPost) -> Result<()> {
    let CreateForumPost {
        nns_proposal_text_paths,
        nns_proposal_ids,
        sns_proposal_text_paths,
        sns_proposal_ids,
    } = cmd;

    let ic = ic_dir();

    // --- Generate NNS forum post ---
    {
        let script = ic.join("testnet/tools/nns-tools/cmd.sh");
        let output = Command::new(script)
            .arg("generate_forum_post_nns_upgrades")
            .args(nns_proposal_text_paths)
            .output()
            .expect("Failed to run generate_forum_post_nns_upgrades");

        if !output.status.success() {
            bail!(
                "Failed to generate NNS forum post: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        copy(&output.stdout)?;

        let title = format!("NNS Updates {}", chrono::Local::now().format("%Y-%m-%d"));
        let body =
            "Please paste the post in here! It should already be copied into your clipboard.";
        let mut url = Url::parse("https://forum.dfinity.org/new-topic")?;
        url.query_pairs_mut()
            .append_pair("title", &title)
            .append_pair("body", body)
            .append_pair("category", "Governance/NNS proposal discussions")
            .append_pair("tags", "nns");

        open_webpage(&url)?;

        use std::fmt::Write;
        println!(
            "NNS forum post copied to clipboard. Please paste in the following proposal texts as well: {}",
            nns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
                let _ = write!(
                    acc,
                    "\n  - https://dashboard.internetcomputer.org/proposal/{}",
                    id
                );
                acc
            })
        );

        press_enter_to_continue()?;
    }

    // --- Generate SNS forum post ---
    {
        let script = ic.join("testnet/tools/nns-tools/cmd.sh");
        let output = Command::new(script)
            .arg("generate_forum_post_sns_wasm_publish")
            .args(sns_proposal_text_paths)
            .output()
            .expect("Failed to run generate_forum_post_sns_wasm_publish");

        if !output.status.success() {
            bail!(
                "Failed to generate SNS forum post: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        copy(&output.stdout)?;

        let title = format!("SNS Updates {}", chrono::Local::now().format("%Y-%m-%d"));
        let body =
            "Please paste the post in here! It should already be copied into your clipboard.";
        let mut url = Url::parse("https://forum.dfinity.org/new-topic")?;
        url.query_pairs_mut()
            .append_pair("title", &title)
            .append_pair("body", body)
            .append_pair("category", "Governance/NNS proposal discussions")
            .append_pair("tags", "SNS");

        open_webpage(&url)?;

        use std::fmt::Write;
        println!(
            "SNS forum post copied to clipboard. Please paste in the following proposal texts as well: {}",
            sns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
                let _ = write!(
                    acc,
                    "\n  - https://dashboard.internetcomputer.org/proposal/{}",
                    id
                );
                acc
            })
        );

        press_enter_to_continue()?;
    }

    print_step(
        6,
        "Post to the DFINITY forum",
        "Make sure to add the proposal IDs to the forum post!",
    )?;

    // Continue to the next automated step.
    run_schedule_vote(ScheduleVote {
        nns_proposal_ids,
        sns_proposal_ids,
    })
}

fn run_schedule_vote(cmd: ScheduleVote) -> Result<()> {
    let ScheduleVote {
        nns_proposal_ids,
        sns_proposal_ids,
    } = cmd;

    if nns_proposal_ids.is_empty() && sns_proposal_ids.is_empty() {
        println!("No proposals to schedule vote for.");
        return Ok(());
    }

    use std::fmt::Write;

    let instructions = format!(
        "Vote YES on the following proposals:
NNS: {}
SNS: {}",
        nns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
            let _ = write!(
                acc,
                "\n  - http://dashboard.internetcomputer.org/proposal/{}",
                id
            );
            acc
        }),
        sns_proposal_ids.iter().fold(String::new(), |mut acc, id| {
            let _ = write!(
                acc,
                "\n  - http://dashboard.internetcomputer.org/proposal/{}",
                id
            );
            acc
        }),
    );

    println!("Copying instructions for Trusted Neurons to clipboard...");
    copy(instructions.as_bytes())?;
    input("Press Enter to open the calendar event...")?;
    open_webpage(&Url::parse("https://calendar.google.com/calendar/u/0/r/eventedit/duplicate/MjJvMTdva2xtdGJuZDhoYjRjN2poZzNwM2ogY182NGYwZDdmZDYzYjNlMDYxZjE1Zjk2MTU1NWYzMmFiN2EyZmY3M2NjMWJmM2Q3ZTRkNGI3NGVjYjk1ZWVhM2M0QGc")?)?;

    print_step(7,
        "Schedule Trusted Neurons Vote",
        "Schedule calendar event for Trusted Neurons to vote the following Monday.

Calendar Event Setup:
1. Duplicate a past event from:
   https://calendar.google.com/calendar/u/0/r/eventedit/duplicate/MjJvMTdva2xtdGJuZDhoYjRjN2poZzNwM2ogY182NGYwZDdmZDYzYjNlMDYxZjE1Zjk2MTU1NWYzMmFiN2EyZmY3M2NjMWJmM2Q3ZTRkNGI3NGVjYjk1ZWVhM2M0QGc

2. Use 'NNS Upgrades' calendar

3. Timing:
   - Usually scheduled at 6 pm Central European Time
   - For multiple proposals, schedule separate sequential events

4. Required Fields:
   - Date and Time
   - Title: Include canister name and proposal ID
   - Description: Link to the proposal

5. Actions:
   - Click 'Save' to create event
   - Send email invitations when prompted
   - If people don't respond, ping @trusted-neurons in #eng-release channel",
    )?;

    run_update_changelog(UpdateChangelog)
}

fn run_update_changelog(_: UpdateChangelog) -> Result<()> {
    print_step(
        8,
        "Update Changelog",
        "Update CHANGELOG.md file(s) for each proposal:

1. For each proposal ID:
   ```bash
   PROPOSAL_IDS=...

   for PROPOSAL_ID in $PROPOSAL_IDS do
       ./testnet/tools/nns-tools/add-release-to-changelog.sh \\
           $PROPOSAL_ID
   done
   ```

2. Best Practice:
   - Combine this change with mainnet-canisters.json update in the same PR",
    )?;

    println!("{}", "\nRelease process complete!".bright_green().bold());
    println!("Please verify that all steps were completed successfully.");

    Ok(())
}
