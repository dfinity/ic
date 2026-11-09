---
name: upgrade-governance-backend
description: >
  Guide the governance backend canister upgrade process — pick RC commit,
  determine targets, create proposal texts, submit proposals, create forum
  posts, schedule votes, and update changelogs.
---

# NNS/SNS Canister Release

This skill orchestrates the NNS and SNS canister release process. It replaces the
`release-runscript` binary (`rs/nervous_system/tools/release-runscript`) by calling
the same underlying bash scripts directly.

All commands should be run from the repository root. Prefix commands with
`cd "$(git rev-parse --show-toplevel)"` to ensure this.

## Prerequisites

1. Switch to an up-to-date master branch so the release scripts match the latest code:
   ```
   cd "$(git rev-parse --show-toplevel)" && git checkout master && git pull
   ```

2. Run `gh auth status` to check if `gh` is authenticated with `github.com`.
   If not, run:
   ```
   gh auth login --hostname github.com --git-protocol ssh --skip-ssh-key --web
   ```
   This prints a one-time device code and a URL. Instruct the user to open the
   URL in their browser and enter the code. **Do not** use bare `gh auth login`,
   as the interactive prompts are unreliable when run from an AI agent.

3. Verify remaining prerequisites:
   ```
   brew list coreutils >/dev/null && bazel --version
   ```
   If any tool is missing, guide the user:
   - `coreutils`: `brew install coreutils` (needed for `gdate` in changelog scripts)
   - `bazel`: `brew install bazelisk`

Also check for optional tools and inform the user what will be automated vs manual:
- **Slack MCP** (`mcp__plugin_slack_slack__*`): if available, will stage a Slack
  draft for `#dev-nns` and copy the channel-topic text to the clipboard. If not,
  will print the message and topic for manual posting.

  To install: run `/plugin install slack@claude-plugins-official` in Claude Code
  (the plugin lives in the official `anthropics/claude-plugins-official`
  marketplace, which is preconfigured). On first use you'll be prompted to
  authenticate with your Slack workspace.

## Step 1: Pick Release Candidate Commit

Use the commit of the most recent **successful** `Schedule Daily` run:
```
gh run list \
    --repo dfinity/ic \
    --workflow schedule-daily.yml \
    --limit 6 \
    --json headSha,createdAt,conclusion,status,databaseId
```
Take the `headSha` of the newest entry with `"conclusion": "success"`.

Then confirm that commit's post-merge `CI Main` run passed its tests and
uploaded the prebuilt artifacts that the proposal scripts download:
```
gh api repos/dfinity/ic/commits/$RC_COMMIT/check-runs \
    --paginate \
    --jq '.check_runs[] |
        select(
             .name == "CI Main / Bazel Test All"
             or .name == "CI Main / Build IC"
             or .name == "CI Main / Upload external artifacts"
        )
        | "\(.check_suite.id) | \(.name) | \(.status) | \(.conclusion) | \(.details_url)"'
```
Each of these checks usually appears twice: once from the merge-queue run, where
`Build IC` and `Upload external artifacts` are `skipped`, and once from the
post-merge master run. Look at the master run, the one where `Build IC` was not
skipped. All three checks there must be `completed` / `success`. If they are not,
fall back to the next-newest successful `Schedule Daily` run.

Ask the user to confirm the commit or provide an override.

Store the chosen commit as `RC_COMMIT` for all subsequent steps.

## Step 2: Determine Upgrade Targets

Run:
```
./rs/nervous_system/tools/release/list-new-commits.sh $RC_COMMIT
```

Parse the output to categorize each canister:
- **Interesting commits**: canisters with at least one `feat` or `fix` commit
  (shown in green by the script). These are strong candidates for release.
- **Chore-only commits**: canisters where every commit is chore, refactor, test,
  or docs. Generally skip these unless there is a reason to release.

The script decides "interesting" from the conventional commit prefix alone, and
prefixes are often wrong: a `fix:` can be a pure deduplication, and a `feat:`
can be a dependency migration that keeps behavior identical. Before presenting
the results, confirm each `feat`/`fix` commit:

1. Read the commit's diff restricted to the canister's code, e.g.
   `git show $COMMIT -- rs/nns/cmc/ rs/nervous_system/runtime/`. Include shared
   libraries the canister depends on, not just its own directory.
2. Check whether the commit added an entry to the canister's
   `unreleased_changelog.md`. An entry is strong evidence that the author
   considers the change user-visible; no entry is a hint (not proof) that it is
   not. There is a reminder bot that tells people to add changelog entries.
   In practice, it's pretty effective, but not always.
3. Decide whether the canister's observable behavior changes: its API, its
   responses or error codes, its state, or what it does. Refactors,
   deduplication, comment changes, removing `#![allow(deprecated)]`, and
   library upgrades (e.g. moving to a new `ic-cdk` version) that preserve
   behavior are **not** interesting; treat them as chores, whatever their
   prefix says. Do not trust the commit message on this; it can describe
   behavior that the code does not actually implement.

Reclassify commits that do not change behavior as uninteresting, and briefly
tell the user why (e.g. "dedups an identical error mapping; codes unchanged").
A canister whose only interesting-by-prefix commits fail this check becomes a
SKIP.

The reverse also happens: a `chore:` or `refactor:` commit that adds an
`unreleased_changelog.md` entry changes behavior, so count it as interesting.
Reading each canister's `unreleased_changelog.md` at `$RC_COMMIT` (e.g.
`git show $RC_COMMIT:rs/registry/canister/unreleased_changelog.md`) is a quick
way to catch these.

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

**Usually this step is already done by Schedule Daily.** Its `Bazel Test NNS
Nightly` job runs this same test with `NNS_CANISTER_UPGRADE_SEQUENCE=all`, which
upgrades every NNS canister. So if `RC_COMMIT` came from a successful Schedule
Daily run (step 1), confirm that the test actually ran and passed in that run,
and then skip the rest of this step:

```
gh run view \
    $SCHEDULE_DAILY_RUN_ID \
    --repo dfinity/ic \
    --json jobs \
    --jq '.jobs[]
        | select(.name == "Bazel Test NNS Nightly")
        | .databaseId'

# Pass the job ID printed by the previous command as $JOB_ID.
gh run view \
    $SCHEDULE_DAILY_RUN_ID \
    --repo dfinity/ic --job $JOB_ID --log \
    | grep -E 'upgrade_canisters_with_golden_nns_state .*(PASSED|FAILED|FLAKY)'
```

(`$SCHEDULE_DAILY_RUN_ID` is the `databaseId` of the Schedule Daily run chosen in
step 1.) Expect a line like

```
//rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state PASSED in 1207.2s
```

If the result says `(cached) PASSED`, the test passed against an older copy of
the golden NNS state; ask the user whether that is acceptable or the test should
be re-run as described below. Likewise if it says `FLAKY`: the job runs with
`--config=flaky_retry`, so the test failed at least once before passing on a
retry.

If `RC_COMMIT` did not come from a successful Schedule Daily run (e.g. the user
overrode it), run the NNS canister upgrade dress rehearsal test as follows. This
ensures selected NNS canisters remain upgradeable (no panic during pre-upgrade).
The test uses golden NNS state.

Before running, check that the working tree is clean (`git status --porcelain`). If
there are uncommitted changes, warn the user — `git checkout` will fail or lose work.

Build the fully-substituted command with `$RC_COMMIT` and
`$NNS_CANISTERS_CSV` replaced by their actual values (e.g.
`governance,registry,root`):

```
git checkout $RC_COMMIT && \
bazel test \
    --test_env=SSH_AUTH_SOCK \
    --test_env=NNS_CANISTER_UPGRADE_SEQUENCE=$NNS_CANISTERS_CSV \
    --test_output=streamed \
    --test_arg=--nocapture \
    --test_timeout=3600 \
    //rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state
```

This test may require a supported environment (e.g. devenv). Ask the user how
they want to run it:
1. **Run locally** — execute the command directly in the session
2. **Run via MCP** — use a remote bazel MCP tool if one is available
3. **Print only** — output the command for the user to copy-paste into their
   own environment (e.g. devenv)

This test can take 5-15 minutes. Proceed to step 4 (creating proposal texts)
in parallel while the test runs, but do not proceed to step 5 (submission)
until the test passes.

## Step 4: Create Proposal Texts

Capture the release date once and reuse it for all commands in this step:
`RELEASE_DATE=$(date +%Y-%m-%d)`. Use `$RELEASE_DATE` consistently below.

Create a proposals directory:
```
mkdir -p ../proposals/release-$RELEASE_DATE
```

For each NNS canister, run:
```
./rs/nervous_system/tools/release/prepare-nns-upgrade-proposal-text.sh \
    $CANISTER $RC_COMMIT \
    > ../proposals/release-$RELEASE_DATE/nns-$CANISTER.md
```

Special case: for `cycles-minting`, ask the user for an upgrade arg
(default `()`), then:
```
./rs/nervous_system/tools/release/prepare-nns-upgrade-proposal-text.sh \
    cycles-minting $RC_COMMIT "()" \
    > ../proposals/release-$RELEASE_DATE/nns-cycles-minting.md
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

Instruct the user to:
1. Plug in their HSM key and unplug their YubiKey
2. Test hardware, with either of:
   - `pkcs11-tool --list-slots`: quick check that the HSM is detected.
   - `pkcs11-tool --login --test`: more thorough. It prompts for the HSM PIN, so
     it also confirms that the PIN works before any proposal is submitted.

Then, print the exact commands for the user to run in a **separate terminal / tmux pane**.
Use the actual proposals directory path (e.g. `../proposals/release-2026-04-06`), not a
variable. Each command should `tee` its output to a file so Claude can read the proposal
IDs afterward.

For each NNS proposal:
```
./rs/nervous_system/tools/release/submit-mainnet-nns-upgrade-proposal.sh \
    ../proposals/release-YYYY-MM-DD/nns-$CANISTER.md \
    $NEURON_ID \
    2>&1 \
    | tee /tmp/proposal-nns-$CANISTER.out
```

For each SNS proposal:
```
./rs/nervous_system/tools/release/submit-mainnet-publish-sns-wasm-proposal.sh \
    ../proposals/release-YYYY-MM-DD/sns-$CANISTER.md \
    $NEURON_ID \
    2>&1 \
    | tee /tmp/proposal-sns-$CANISTER.out
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

The generated post includes the vote date (3 calendar days from today),
computed by the script. Verify it looks correct.

After resolving TODOs, write the final forum post to a file
(e.g. `/tmp/forum-post-nns.md`) and copy it to the clipboard:
```
pbcopy < /tmp/forum-post-nns.md
```

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

Instruct the user to create a Google Calendar event:
1. Click the 11 AM CET slot, 3 calendar days from today (use the user's local
   date). E.g. Friday → Monday, Monday → Thursday, Tuesday → Friday.
2. Put it on the "NNS Upgrades" calendar.
3. Title: Upgrade NNS & SNS (drop whichever has no proposals)
4. Description: paste from the clipboard.

Before giving these instructions, write the description to a file and copy it to
the clipboard (`pbcopy < $FILE`), so the user only has to paste it. Print the
content and tell the user it has been copied to their clipboard. Google Calendar
does not render Markdown, so use bare URLs; it turns them into links. Only
include sections (NNS / SNS) that have proposals. Format:
```
NNS:
- Governance: https://dashboard.internetcomputer.org/proposal/$ID
- Registry: https://dashboard.internetcomputer.org/proposal/$ID

SNS:
- Root: https://dashboard.internetcomputer.org/proposal/$ID
```

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
2. Commit only the changed changelog files, by passing their paths to
   `git commit` (e.g. `git commit -m "chore(nervous-system): update changelog"
   -- rs/registry/canister/CHANGELOG.md rs/registry/canister/unreleased_changelog.md ...`).
   With paths, `git commit` commits only those files and leaves anything else
   the user has staged untouched. Do NOT use `git add .` or a bare `git commit`;
   either may pick up unrelated files.
3. Push: `git push --set-upstream origin changelog-update-YYYY-MM-DD`
4. Create the PR, **not** as a draft, even though `CLAUDE.md` says PRs should
   be drafts:
   ```
   gh pr create \
       --title "chore(nervous-system): Update changelog for release YYYY-MM-DD" \
       --body "Update CHANGELOG.md for today's release."
   ```
   The PR is opened under whichever account `gh` is signed in as, which is
   normally the user's own, so the user cannot approve it themselves; someone
   else has to.

   Do **not** request a Copilot review on this PR, even though `CLAUDE.md` says
   to request one for every PR. Its content is generated entirely by
   `add-release-to-changelog.sh` (entries moved from `unreleased_changelog.md`
   into `CHANGELOG.md`), so there is nothing for Copilot to review.

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

If Slack MCP tools are available (`mcp__plugin_slack_slack__*`), use the
`slack_send_message_draft` tool to stage a draft message for the user to
review before sending (this is a Slack MCP tool that creates a message
draft visible only to the user). The Slack MCP cannot update channel
topics, so always print the topic text and copy it to clipboard (`pbcopy`)
for the user to paste via `/topic` in Slack.

If Slack MCP is NOT available, print both the message and topic text for the user
to post manually to `#dev-nns`.
