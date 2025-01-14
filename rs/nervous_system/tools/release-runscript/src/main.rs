use colored::*;
use std::io::{self, Write};

struct Step {
    title: &'static str,
    description: &'static str,
}

fn main() {
    let steps = vec![
        Step {
            title: "Pick Release Candidate Commit",
            description: "Run `./testnet/tools/nns-tools/cmd.sh latest_commit_with_prebuilt_artifacts`.
If you would like to pick a different commit, follow these steps:
2. Go to https://github.com/dfinity/ic/actions/workflows/ci-main.yml?query=branch%3Amaster+event%3Apush+is%3Asuccess
3. Find a recent commit with passing CI Main in the master branch
4. Record this commit (e.g., post to Slack)

Pre-built artifacts check:
- Install aws tool if needed
- List available files: 
  aws s3 ls --no-sign-request s3://dfinity-download-public/ic/${COMMIT}/canisters/
- Note: Our tools download from the analogous https://download.dfinity.systems/... URL",
        },
        Step {
            title: "Determine Upgrade Targets",
            description: "Determine which NNS canisters and/or SNS WASMs need to be upgraded/published.
Only those with 'interesting' changes need to be released.

Required checks:
1. Run: ./testnet/tools/nns-tools/list-new-commits.sh
2. Check Monday team sync meeting minutes at:
   https://docs.google.com/document/d/1CPM1RlMz6UMSUQzqvdP7EDiLMomK4YeuEV7UnxQ9DAE/edit

For SNS ledger suite (ledger, archive, and index canisters):
- Consult Financial Integrations team
- FI team should contact NNS team Friday morning about significant changes
- FI team should provide the 'Features' section of proposals
- This agreement is new - you may need to remind them
- This applies to ledger, archive, and index canisters",
        },
        Step {
            title: "Run NNS Upgrade Tests",
            description: "Verify the commit you chose at the previous step has a green check on this page: https://github.com/dfinity/ic/actions/workflows/ci-main.yml?query=branch:master+event:push+is:success

If not, you can also run the upgrade tests manually:
    - Follow instructions in: testnet/tools/nns-tools/README.md#upgrade-testing-via-bazel
   
2. SNS Testing Note:
   - No manual testing needed for SNS
   - Covered by sns_release_qualification in CI
   - Example: Test at rs/nervous_system/integration_tests/tests/sns_release_qualification.rs",
        },
        Step {
            title: "Create Proposal Texts",
            description: "Create proposal text for each canister to be upgraded.
This can be done in parallel with the previous testing step.

Instructions:
1. Follow format in: testnet/tools/nns-tools/README.md#nnssns-canister-upgrade-proposal-process
2. Name conventions:
   - NNS proposals: nns-*.md
   - SNS proposals: sns-*.md
3. Organization:
   - Put all proposal files in a dedicated directory
   - Keep directory clean (nothing else in there)
   - This will help with forum post generation later",
        },
        Step {
            title: "Submit Proposals",
            description: "Submit the proposals on Friday

Follow detailed instructions at:
testnet/tools/nns-tools/README.md#submit-the-proposals",
        },
        Step {
            title: "Create Forum Post",
            description: "Create a forum post with the following specifications:

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
        },
        Step {
            title: "Schedule Trusted Neurons Vote",
            description: "Schedule calendar event for Trusted Neurons to vote the following Monday.

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
        },
        Step {
            title: "Update Mainnet Canisters",
            description: "After proposal execution, update mainnet-canisters.json:

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
        },
        Step {
            title: "Update Changelog",
            description: "Update CHANGELOG.md file(s) for each proposal:

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
        },
    ];

    println!("{}", "\nNNS Release Runscript".bright_green().bold());
    println!("{}", "===================".bright_green());
    println!("This script will guide you through the NNS release process.\n");

    for (index, step) in steps.iter().enumerate() {
        print_step(index + 1, step);

        print!("\nPress Enter to continue to next step...");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        // Clear screen for next step
        print!("\x1B[2J\x1B[1;1H");
    }

    println!("{}", "\nRelease process complete!".bright_green().bold());
    println!("Please verify that all steps were completed successfully.");
}

fn print_step(number: usize, step: &Step) {
    println!(
        "{} {}",
        format!("Step {}:", number).bright_blue().bold(),
        step.title.white().bold()
    );
    println!("{}", "---".bright_blue());
    println!("{}\n", step.description);
}
