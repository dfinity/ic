use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
struct CreateForumPost;

#[derive(Debug, Parser)]
struct ScheduleVote;

#[derive(Debug, Parser)]
struct UpdateCanistersJson;

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
    #[command(about = "Step 8: Update Mainnet Canisters")]
    UpdateCanistersJson(UpdateCanistersJson),
    #[command(about = "Step 9: Update Changelog")]
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

fn ic_dir() -> PathBuf {
    let workspace_dir =
        std::env::var("BUILD_WORKSPACE_DIRECTORY").expect("BUILD_WORKSPACE_DIRECTORY not set");
    PathBuf::from(&workspace_dir)
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
        Some(Step::UpdateCanistersJson(cmd)) => run_update_canisters_json(cmd),
        Some(Step::UpdateChangelog(cmd)) => run_update_changelog(cmd),
    }

    Ok(())
}

fn run_pick_commit() {
    // Get the ic directory.
    let ic = ic_dir();

    // Build the absolute path to the cmd.sh script.
    let cmd_path = ic.join("testnet/tools/nns-tools/cmd.sh");

    // Run the command with the required argument.
    let output = Command::new(cmd_path)
        .arg("latest_commit_with_prebuilt_artifacts")
        .current_dir(&ic)
        .output()
        .unwrap();

    let commit = if output.status.success() {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("A commit with prebuilt artifacts was found with the following command: `./testnet/tools/nns-tools/cmd.sh latest_commit_with_prebuilt_artifacts`.");
        input_with_default("Commit to release", &commit)
    } else {
        println!(
            "Automatically determining the commit hash failed with error:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // get input from user for the commit
        input("Enter the commit hash, which you can find by running `./testnet/tools/nns-tools/cmd.sh latest_commit_with_prebuilt_artifacts`")
    };

    print_step(
        1,
        "Pick Release Candidate Commit",
        &format!("Chosen commit: {}", commit),
    );

    // Continue to next step.
    run_determine_targets(DetermineTargets { commit });
}

fn run_determine_targets(cmd: DetermineTargets) {
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
        if input_yes_or_no(&format!("   Release {}?", canister), false) {
            nns_canisters.push(canister.to_string().to_lowercase());
        }
    }

    // Ask about SNS canisters.
    println!("SNS canisters:");
    for &canister in sns_candidates.iter() {
        if input_yes_or_no(&format!("   Release {}?", canister), false) {
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
    );

    run_run_tests(RunTests {
        commit,
        nns_canisters,
        sns_canisters,
    });
}

fn run_run_tests(cmd: RunTests) {
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
    );

    run_create_proposal_texts(CreateProposalTexts {
        commit,
        nns_canisters,
        sns_canisters,
    });
}

fn run_create_proposal_texts(cmd: CreateProposalTexts) {
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
        std::fs::remove_dir_all(&proposals_dir).unwrap();
    }
    std::fs::create_dir_all(&proposals_dir).expect("Failed to create proposals directory");

    let proposals_dir = proposals_dir.canonicalize().unwrap();

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
            let upgrade_arg = input_with_default("Upgrade arg for CMC?", "'()'");
            Command::new(script)
                .arg(canister)
                .arg(&commit)
                .arg(upgrade_arg)
                .current_dir(&ic)
                .output()
                .expect("Failed to run NNS proposal text script")
        };
        if !output.status.success() {
            panic!(
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
            panic!(
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
    );

    run_submit_proposals(SubmitProposals {
        nns_proposal_text_paths,
        sns_proposal_text_paths,
    });
}

fn run_submit_proposals(cmd: SubmitProposals) {
    let SubmitProposals {
        nns_proposal_text_paths,
        sns_proposal_text_paths,
    } = cmd;

    // Ask the user for the SUBMITTING_NEURON_ID (example: 51)
    if input_yes_or_no("Do you want to submit upgrade proposals?", false) {
        println!("Skipping upgrade proposal submission and all following steps.");
        return;
    }
    println!();

    println!("We are now going to submit the proposals. For this step, we need your neuron ID. If you are submitting on behalf of DFINITY, your neuron ID is written at this notion page: <https://www.notion.so/dfinityorg/3a1856c603704d51a6fcd2a57c98f92f?v=fc597afede904e499744f3528cad6682>.");
    let neuron_id = input("Enter your neuron ID (e.g. 51)");

    println!("Plug in your HSM key. Unplug your Ubikey.");
    println!("Once you have done that, you can test your key hardware with the following command:");
    println!("    pkcs11-tool --list-slots");
    println!("And you can practice entering your password with: ");
    println!("    pkcs11-tool --login --test");
    input("Press Enter to continue...");

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
            panic!(
                "Submission failed for {}: {}",
                proposal_path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!("Submission successful for {}", proposal_path.display());
        nns_proposal_ids.push(input("Enter the proposal ID"));
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
            panic!(
                "Submission failed for {}: {}",
                proposal_path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!("Submission successful for {}", proposal_path.display());
        sns_proposal_ids.push(input("Enter the proposal ID"));
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
    );

    run_create_forum_post(CreateForumPost);
}

fn run_create_forum_post(_: CreateForumPost) {
    print_step(6,
        "Create Forum Post",
        "Create a forum post with the following specifications:

1. Title Format: 
   'NNS Updates <ISO 8601 DATE>(: <Anything interesting to announce>)'

2. Category: 
   Governance > NNS proposal discussion
   Reference: https://forum.dfinity.org/t/nns-proposal-discussions/34492

3. Tags:
   - Protocol-canister-management / Service-nervous-system-management
   - nns / sns

4. Content:
   - Link to proposals in IC Dashboard
   - Include all proposal texts
   - Use six consecutive backticks (```````) to wrap proposal text
   - Call out any 'interesting' changes, breaking changes, or required actions

5. Generate Forum Content:
   If your proposals are in a dedicated directory:

   For NNS upgrades:
   ```bash
   ./testnet/tools/nns-tools/cmd.sh \\
       generate_forum_post_nns_upgrades \\
       $PROPOSALS_DIR/nns-*.md \\
       | pbcopy
   ```

   For SNS WASM publishing:
   ```bash
   ./testnet/tools/nns-tools/cmd.sh \\
       generate_forum_post_sns_wasm_publish \\
       $PROPOSALS_DIR/sns-*.md \\
       | pbcopy
   ```

6. Required Follow-ups:
   - Reply to NNS Updates Aggregation Thread (https://forum.dfinity.org/t/nns-updates-aggregation-thread/23551)
   - If SNS canister WASMs were published, update SNS Upgrades Aggregation Thread
     (https://forum.dfinity.org/t/sns-upgrade-aggregation-thread/24259/2)",
    );

    run_schedule_vote(ScheduleVote);
}

fn run_schedule_vote(_: ScheduleVote) {
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
    );

    run_update_canisters_json(UpdateCanistersJson);
}

fn run_update_canisters_json(_: UpdateCanistersJson) {
    print_step(
        8,
        "Update Mainnet Canisters",
        "After proposal execution, update mainnet-canisters.json:

1. Run the sync command:
   bazel run //rs/nervous_system/tools/sync-with-released-nevous-system-wasms

   Note: If you encounter problems, try adding --config=local

2. Purpose of these changes:
   - Tells bazel what versions are running in production
   - Used by tests to verify upgrade compatibility
   - Maintains build hermeticity

3. Note on automation:
   - There was a ticket for automating this (NNS1-2201)
   - Currently marked as won't do",
    );

    run_update_changelog(UpdateChangelog);
}

fn run_update_changelog(_: UpdateChangelog) {
    print_step(
        9,
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
    );

    println!("{}", "\nRelease process complete!".bright_green().bold());
    println!("Please verify that all steps were completed successfully.");
}

fn print_header() {
    println!("{}", "\nNNS Release Runscript".bright_green().bold());
    println!("{}", "===================".bright_green());
    println!("This script will guide you through the NNS release process.\n");
}

fn print_step(number: usize, title: &str, description: &str) {
    println!(
        "{} {}",
        format!("Step {}:", number).bright_blue().bold(),
        title.white().bold()
    );
    println!("{}", "---".bright_blue());
    println!("{}\n", description);
    print!("\nPress Enter to continue to next step...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    print!("\x1B[2J\x1B[1;1H");
}

fn input(text: &str) -> String {
    print!("{}: ", text);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn input_with_default(text: &str, default: &str) -> String {
    let input = input(&format!("{} (default: {})", text, default));
    if input.is_empty() {
        default.to_string()
    } else {
        input
    }
}

fn input_yes_or_no(text: &str, default: bool) -> bool {
    loop {
        let input = input(&format!(
            "{} {}",
            text,
            if default {
                "Y/n (default: yes)"
            } else {
                "y/N (default: no)"
            }
        ));
        if input.is_empty() {
            return default;
        } else if input.to_lowercase() == "y" {
            return true;
        } else if input.to_lowercase() == "n" {
            return false;
        }
    }
}
