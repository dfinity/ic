---
name: fix-flaky-tests
description: Use this when asked to fix flaky bazel tests.
---

This guide explains how to find flaky tests to fix and how to debug them. Flaky tests are bazel tests that run on GitHub workflows that pass after having failed in a previous attempt.

# Prerequisites

1. Make sure you're on an up-to-date `master` branch to ensure you're using and reading the latest code:
   ```
   git checkout master && git pull
   ```

2. Run `gh auth status` to check if `gh` is authenticated with `github.com` using `Git operations protocol: ssh`.

   If not run:
   ```
   gh auth login --hostname github.com --git-protocol ssh --skip-ssh-key --web
   ```
   This prints a one-time device code and a URL. Instruct the user to open the URL in their browser and enter the code.

   **Do not** use the bare `gh auth login` command, as the interactive prompts are unreliable when run from an AI agent.

# Fix a flaky test

1. If not instructed to fix a test with a specified `label` determine which test to fix by picking the most flaky test in the last week which has not yet been fixed. To do this:

    1. Run the following command to get the top 100 tests ordered descendingly by how much percent of their total runs they flaked in the last week, showing only tests which flaked 1% or more of their runs:
       ```
       bazel run //ci/githubstats:query -- top 100 flaky% --ge 1 --week
       ```

    2. Pick the `label` of the top most test which doesn't have an open PR or git commit in the last week mentioning its `<test_name>` which is the part of the `label` after the `:`.

       `<test_name>` might be suffixed with `_head_nns` or `_colocate` which are variants of the same test. Strip those suffixes when checking for open PRs or commits to avoid missing matches.

       To check if there is an open PR mentioning the test, run the following command:
       ```
       gh pr list --search "<test_name>" --state open
       ```

       To check if there is a git commit mentioning the test, run the following command:
       ```
       git log --since 'last week' | grep <test_name>
       ```

       Continue with the next test if you find an open PR or commit mentioning `<test_name>`
       even if it seems the commit is not about fixing flakiness.
       It's better to pick a test which has no other work being done on it to avoid conflicts.

2. Get the last flaky runs of the test named `label` in the last week by running the following command, replacing `<label>` with the label of the test:
   ```
   bazel run //ci/githubstats:query -- last --flaky --week --download-ic-logs --download-console-logs <label>
   ```
   Note the command will print `Downloading logs to: <LOG_DIR>`.

   Read `<LOG_DIR>/README.md` to understand how the logs are organized.

3. Analyze the source code of `label` and the logs in `<LOG_DIR>` to determine the root cause of the flakiness.

4. Once you have determined the root cause,
   fix the test taking `.claude/CLAUDE.md` into account.

5. Verify the test still passes by running:
   ```
   bazel test --test_output=errors --runs_per_test=3 --jobs=3 <label>
   ```
   This executes 3 runs of the test in parallel to increase the chances of reproducing the flakiness. If it fails, analyze the failure and fix it until it passes reliably.

6. Make a draft Pull Request with the fix, following these steps:

   1. From the root of the repository, create a new git branch named `ai/deflake-<test_name>-<date>`,
      replacing `<test_name>` with the name of the test
      and `<date>` with the current date in `YYYY-MM-DD` format,
      and commit your fix to that branch.

   2. Submit a draft PR using `gh` with the fix.
      Name it: `fix: deflake <label>`.
      Include the root cause analysis in the PR description
      and mention the PR was created following the steps in `.claude/skills/fix-flaky-tests/SKILL.md`.
