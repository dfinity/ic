---
name: nns-sns-release
description: Guide the NNS/SNS canister release process — pick RC commit, determine targets, create proposal texts, submit proposals, create forum posts, schedule votes, and update changelogs.
---

# NNS/SNS Canister Release

This skill orchestrates the NNS and SNS canister release process. It replaces the
`release-runscript` binary (`rs/nervous_system/tools/release-runscript`) by calling
the same underlying bash scripts directly.

All commands should be run from the repository root.

## Prerequisites

Before starting, verify prerequisites with a single command:
```
git fetch origin master --force && gh auth status && brew list coreutils >/dev/null && bazel --version
```
If any tool is missing, guide the user:
- `gh`: `brew install gh && gh auth login`
- `coreutils`: `brew install coreutils` (needed for `gdate` in changelog scripts)
- `bazel`: `brew install bazelisk`

Also check for optional tools and inform the user what will be automated vs manual:
- **Slack MCP** (`mcp__plugin_slack_slack__*`): if available, will auto-post to `#dev-nns`
  and update the channel topic. If not, will print the message and topic for manual posting.

## Step 1: Pick Release Candidate Commit

Run:
```
./rs/nervous_system/tools/release/cmd.sh latest_commit_with_prebuilt_artifacts
```

This returns the latest master commit with prebuilt artifacts. If it does not match
`origin/master` HEAD, the artifacts are not ready yet. Poll every 2 minutes in the
background (using Bash tool's `run_in_background` option) until they match. The user
can continue other work while waiting. If artifacts have not appeared after 20 minutes,
warn the user that CI may be broken and ask whether to continue waiting or use the
latest available commit.

Ask the user to confirm the commit or provide an override.

Store the chosen commit as `RC_COMMIT` for all subsequent steps.

## Step 2: Determine Upgrade Targets

Run:
```
./rs/nervous_system/tools/release/list-new-commits.sh $RC_COMMIT
```

Parse the output to categorize each canister:
- **Interesting commits**: canisters with at least one non-chore/refactor/test/docs commit (shown in green by the script). These are strong candidates for release.
- **Chore-only commits**: canisters with commits but all are chore/refactor/test/docs. Generally skip these unless there is a reason to release.
- **No new commits**: canisters with zero commits since last release. Do not release.

**Exclude SNS ledger, index, and archive** from this process. The ICRC ledger suite
(ledger/index/archive) is released separately by the DeFi team on a different cadence
and commit. Do not show them in the table or suggest them for release.

Present each canister group (NNS, then SNS) to the user. For each canister, show:
- The canister name, total commit count, and interesting commit count
- **All commits** listed underneath, with interesting commits marked with `>>>` prefix
  to distinguish them from chore/refactor/test/docs commits
- A recommendation: RELEASE (has interesting commits) / SKIP (chore-only or no commits)

Example format:
```
### NNS governance (4 commits, 2 interesting) — RELEASE
  >>> 077cec5e8f feat(nns): tag 8-year gang bonus base ...
  >>> 1855b0fd98 feat(NNS): add snapshot visibility ...
      a0034d3203 chore(nervous-system): update changelog
      b608c374f2 chore: 42u64 -> 42_u64

### NNS root (2 commits, 0 interesting) — SKIP
      5458e72af6 chore(governance): Add separator ...
      a5e8364794 docs(governance): Updated changelogs ...
```

After presenting all canisters, pre-select those with interesting commits and ask
the user to confirm or adjust the selection. The user can add or remove canisters.

Store the selected canisters as `NNS_CANISTERS` and `SNS_CANISTERS`.

## Step 3: Run NNS Upgrade Tests

**Skip this step if no NNS canisters were selected** (i.e. only SNS canisters).

Run the NNS canister upgrade dress rehearsal test. This ensures selected NNS canisters
remain upgradeable (no panic during pre-upgrade). The test uses golden NNS state.

Before running, check that the working tree is clean (`git status --porcelain`). If
there are uncommitted changes, warn the user — `git checkout` will fail or lose work.

Print the fully-substituted one-liner command to the user before running it, with
`$RC_COMMIT` and `$NNS_CANISTERS_CSV` replaced by their actual values (e.g.
`governance,registry,root`):

```
git checkout $RC_COMMIT && bazel test --test_env=SSH_AUTH_SOCK --test_env=NNS_CANISTER_UPGRADE_SEQUENCE=$NNS_CANISTERS_CSV --test_output=streamed --test_arg=--nocapture --test_timeout=3600 //rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state
```

This test can take 5-15 minutes. Run it in the background (using Bash tool's
`run_in_background` option) so the user can continue working in the session.
Proceed to step 4 (creating proposal texts) in parallel while the test runs,
but do not proceed to step 5 (submission) until the test passes.

SNS upgrade testing is covered by `sns_release_qualification` in CI and does not need
to be run manually.

## Step 4: Create Proposal Texts

Capture the release date once and reuse it for all commands in this step:
`RELEASE_DATE=$(date +%Y-%m-%d)`. Use `$RELEASE_DATE` consistently below.

Create a proposals directory:
```
mkdir -p ../proposals/release-$RELEASE_DATE
```

For each NNS canister, run (note: `2>/dev/null` to avoid stderr warnings leaking into the file):
```
./rs/nervous_system/tools/release/prepare-nns-upgrade-proposal-text.sh $CANISTER $RC_COMMIT 2>/dev/null > ../proposals/release-$RELEASE_DATE/nns-$CANISTER.md
```

Special case: for `cycles-minting`, ask the user for an upgrade arg (default `()`), then:
```
./rs/nervous_system/tools/release/prepare-nns-upgrade-proposal-text.sh cycles-minting $RC_COMMIT "()" 2>/dev/null > ../proposals/release-$RELEASE_DATE/nns-cycles-minting.md
```

For each SNS canister, run:
```
./rs/nervous_system/tools/release/prepare-publish-sns-wasm-proposal-text.sh $CANISTER $RC_COMMIT ../proposals/release-$RELEASE_DATE/sns-$CANISTER.md
```
(Note: the SNS script writes directly to the output file, no `>` redirect needed.)

After generating all proposals, check each file for "TODO" markers. For every
proposal, compare the Features & Fixes section against the interesting commits
identified in step 2 to see if any production changes are missing.

- **"TODO: Review this section"** — the script generated Features & Fixes from the
  unreleased changelog. If all interesting commits are accounted for, simply delete
  the TODO marker paragraph. Do NOT rewrite the script's content. If commits appear
  to be missing, **ask the user** whether to add entries rather than auto-editing.

- **"TODO Hand-craft this section"** — the unreleased changelog was empty:
  1. If any interesting commits from step 2 look like they deserve a changelog entry,
     **ask the user** whether they should be added (PR authors may have misjudged).
  2. If the user confirms none need entries (or all commits are chore/test/docs),
     replace the entire TODO block with: `This is a maintenance release.`

- Show the user the final proposal text for review before proceeding.

Store the proposal file paths as `NNS_PROPOSAL_PATHS` and `SNS_PROPOSAL_PATHS`.

## Step 5: Submit Proposals

**IMPORTANT: This step requires interactive HSM PIN entry, which cannot be done
inside the Claude Code session.**

Check memory for the user's saved neuron ID. If found, pre-fill it and ask the user
to confirm. If not found, ask the user for their neuron ID.
(Lookup: https://www.notion.so/dfinityorg/3a1856c603704d51a6fcd2a57c98f92f?v=fc597afede904e499744f3528cad6682)

Instruct the user to:
1. Plug in their HSM key and unplug their YubiKey
2. Test hardware: `pkcs11-tool --list-slots`

Then, print the exact commands for the user to run in a **separate terminal / tmux pane**.
Use the actual proposals directory path (e.g. `../proposals/release-2026-04-06`), not a
variable. Each command should `tee` its output to a file so Claude can read the proposal
IDs afterward.

For each NNS proposal:
```
./rs/nervous_system/tools/release/submit-mainnet-nns-upgrade-proposal.sh ../proposals/release-YYYY-MM-DD/nns-$CANISTER.md $NEURON_ID 2>&1 | tee /tmp/proposal-nns-$CANISTER.out
```

For each SNS proposal:
```
./rs/nervous_system/tools/release/submit-mainnet-publish-sns-wasm-proposal.sh ../proposals/release-YYYY-MM-DD/sns-$CANISTER.md $NEURON_ID 2>&1 | tee /tmp/proposal-sns-$CANISTER.out
```

Note: Do NOT pipe through `sed` — it buffers output and hides the interactive HSM PIN prompt.

The submit scripts output `proposal NNNNN` in the ic-admin response. After the user
confirms submissions are done, read each `/tmp/proposal-*.out` file and extract the
proposal ID by grepping for `proposal [0-9]+`.

Store proposal IDs as `NNS_PROPOSAL_IDS` and `SNS_PROPOSAL_IDS`.

## Step 6: Create Forum Post

For NNS proposals, run:
```
./rs/nervous_system/tools/release/cmd.sh generate_forum_post_nns_upgrades $NNS_PROPOSAL_PATHS
```

For SNS proposals, run:
```
./rs/nervous_system/tools/release/cmd.sh generate_forum_post_sns_wasm_publish $SNS_PROPOSAL_PATHS
```

The generated post has two TODOs. Resolve them automatically:
1. Replace "TODO proposal links" with links to each proposal:
   `[Proposal NNNNN](https://dashboard.internetcomputer.org/proposal/NNNNN)`
2. Delete the "TODO - delete if nothing relevant" line under Additional Notes
   (or replace with actual notes if the user mentioned breaking changes).

The generated post says "DFINITY plans to vote on these proposals the following Monday."
If today is not Friday, update this to match the actual vote date (3 calendar days from
today, per step 7). E.g. if today is Monday, change to "this Thursday".

After resolving TODOs, write the final forum post to a file (e.g. `/tmp/forum-post-nns.md`).
Copy it to clipboard by checking the `$TMUX` environment variable:
- If `$TMUX` is set: use `tmux load-buffer /tmp/forum-post-nns.md` (user pastes with their tmux paste binding)
- Otherwise: use `pbcopy < /tmp/forum-post-nns.md`

Then provide a pre-filled forum link. Construct the URL with query parameters:

For NNS:
```
https://forum.dfinity.org/new-topic?title=NNS+Updates+YYYY-MM-DD&category=Governance%2FNNS+proposal+discussions&tags=nns%2CProtocol-canister-management
```

For SNS:
```
https://forum.dfinity.org/new-topic?title=SNS+Updates+YYYY-MM-DD&category=Governance%2FNNS+proposal+discussions&tags=SNS%2CService-nervous-system-mgmt
```

The user can paste from tmux buffer with their configured paste binding (typically `prefix + ]`).

After posting, remind the user to reply in the relevant aggregation thread with a link
to the new post. Only mention the thread for the type of release being done:
- If NNS canisters were released: https://forum.dfinity.org/t/nns-updates-aggregation-thread/23551
- If SNS canisters were released: https://forum.dfinity.org/t/sns-upgrade-aggregation-thread/24259

## Step 7: Schedule Trusted Neurons Vote

Provide the user with copy-ready voting instructions. Only include sections (NNS Backend
/ SNS) that have proposals. Format:
```
NNS Backend:
- [Governance: $ID](https://dashboard.internetcomputer.org/proposal/$ID)
- [Registry: $ID](https://dashboard.internetcomputer.org/proposal/$ID)
SNS:
- [Root: $ID](https://dashboard.internetcomputer.org/proposal/$ID)
```

Instruct the user to:
1. Duplicate a past calendar event from:
   https://calendar.google.com/calendar/u/0/r/eventedit/duplicate/MjJvMTdva2xtdGJuZDhoYjRjN2poZzNwM2ogY182NGYwZDdmZDYzYjNlMDYxZjE1Zjk2MTU1NWYzMmFiN2EyZmY3M2NjMWJmM2Q3ZTRkNGI3NGVjYjk1ZWVhM2M0QGc
2. Use the "NNS Upgrades" calendar
3. Schedule at 6 PM CET, 3 calendar days from today (use the user's local date).
   E.g. Friday → Monday, Monday → Thursday, Tuesday → Friday.
4. Title: include canister name and proposal ID
5. Description: link to the proposal
6. Send email invitations when prompted
7. If people do not respond, ping @trusted-neurons in #eng-release

## Step 8: Update Changelog

Switch to the RC commit (detached HEAD):
```
git switch -d $RC_COMMIT
```

For each proposal ID, run:
```
./rs/nervous_system/tools/release/add-release-to-changelog.sh $PROPOSAL_ID
```

After updating changelogs:
1. Create a branch: `changelog-update-YYYY-MM-DD`
2. Stage only the changed changelog files (e.g. `git add rs/nns/governance/CHANGELOG.md
   rs/nns/governance/unreleased_changelog.md rs/registry/canister/CHANGELOG.md ...`).
   Do NOT use `git add .` — it may stage unrelated files.
3. Commit: `git commit -m "chore(nervous-system): update changelog"`
4. Push: `git push --set-upstream origin changelog-update-YYYY-MM-DD`
5. Create a draft PR:
   ```
   gh pr create --draft --title "chore(nervous-system): Update changelog for release YYYY-MM-DD" --body "Update CHANGELOG.md for today's release."
   ```

Tell the user: "PR can be merged before the proposals are executed."

## Step 9: Post to Slack

Prepare the following for `#dev-nns` (private channel — search with `channel_types=private_channel`):

1. **Message:** `PTAL @ release changelog update $PR_URL`

2. **Channel topic update.** Substitute the actual release date (human-readable,
   e.g. `Apr 6, 2026`), RC commit, and canister lists. Format:
   ```
   $RELEASE_DATE:

   RC=$RC_COMMIT

   NNS_CANISTERS=(
       $NNS_CANISTER_LIST
   )

   SNS_CANISTERS=(
       $SNS_CANISTER_LIST
   )
   ```
   Before updating, read the existing channel topic and validate it follows this
   expected format (date, RC=, NNS_CANISTERS, SNS_CANISTERS). If it does not match,
   warn the user instead of overwriting.

If Slack MCP tools are available (`mcp__plugin_slack_slack__*`), create a draft message
using `slack_send_message_draft` so the user can review before sending. The Slack MCP cannot update channel topics, so always print the topic
text and copy it to clipboard (`pbcopy`) for the user to paste via `/topic` in Slack.

If Slack MCP is NOT available, print both the message and topic text for the user
to post manually to `#dev-nns`.
