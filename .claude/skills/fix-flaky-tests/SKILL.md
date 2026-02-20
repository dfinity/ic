---
name: fix-flaky-tests
description: Use this when asked to fix flaky bazel tests.
---

This guide explains how to find flaky tests to fix and how to debug them. Flaky tests are bazel tests that run on GitHub workflows that pass after having failed in a previous attempt.

1. Make sure you're on an up-to-date `master` branch to make sure you're using and reading the latest code:
   ```
   git checkout master && git pull
   ```

2. Determine which flaky bazel test to fix by picking the most flaky test in the last week which has not yet been fixed. To do this:

    1. Run the following command to get the top 10 tests ordered by the number of times they flaked in the last week:
       ```
       bazel run //ci/githubstats:query -- top 10 flaky --week
       ```
    2. Pick the `label` of the top most test which doesn't have an open PR or git commit in the last week mentioning its `<test_name>` which is the part of the `label` after the `:`. Also strip `_head_nns` or `_colocate` from the `<test_name>` to get a more fuzzy match.

       To check if there is a git commit mentioning the test, run the following command:
       ```
       git log --since 'last week' | grep <test_name>
       ```
       Continue with the next test if you find an open PR or commit mentioning `<test_name>`
       even if it seems the commit is not about fixing flakiness.
       It's better to pick a test which has no other work being done on it to avoid conflicts.

3. Get the last flaky runs of the test named `label` in the last week by running the following command, replacing `<label>` with the label of the test:
   ```
   bazel run //ci/githubstats:query -- last --flaky --week --download-ic-logs --download-console-logs <label>
   ```
   Note the command will print `Downloading logs to: <LOG_DIR>`.

   The directory `<LOG_DIR>` will contain an "invocation" directory, named like `<bazel_invocation_timestamp>_<bazel_invocation_id>`,
   per bazel invocation that had a flaky run of the test.

   That invocation directory will have a directory per attempt of the test, named like `1`, `2`, `3`, etc.

   Each attempt directory will either contain a `FAILED.log` or `PASSED.log` file with the log of the test if the attempt failed or passed, respectively.

   In case the test was a system-test, i.e. when the `label` starts with `//rs/tests/`, the attempt directory will also contain:
   * an `ic_logs` directory containing the logs of IC nodes that were deployed as part of the test.
     Each IC node will have its own log file named `<node_id>.log` and there will be a symlink pointing to it with the IPv6 of the node: `<node_IPv6>.log`.
   * a `console_logs` directory containing a `<vm_name>.log` file for each VM deployed as part of the test containing the console output of that VM. Often `<vm_name>` equals `<node_id>`.

4. Analyze the source code of `label` and the logs in `<LOG_DIR>` to determine the root cause of the flakiness.

5. Once you have determined the root cause, fix the test.

6. Run `bazel test <label>` to verify the test still passes.

7. Create a new git branch named like `ai/deflake-<test_name>`, replacing `<test_name>` with the name of the test
   and commit your fix to that branch.

8. Submit a draft PR with the fix.
   Name it: `fix: deflake <label>`.
   Include the root cause analysis in the PR description and link to this `SKILL.md` file.
