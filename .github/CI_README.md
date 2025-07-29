GitHub CI for the IC Repo

## Workflows & Jobs

### CI Main

Workflow *'CI Main'* is the core of CI and is also the only workflow relevant for external PRs.

| Job Name                  | Runner / Image                   | Secrets Required                      | When Invoked                                                                                               | Purpose                                                                                      | External PR |
|---------------------------|----------------------------------|---------------------------------------|------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|-------------|
| config                    | ubuntu-latest                    | None                                  | On any trigger (push, PR, merge_group, workflow_dispatch, workflow_call)                                   | Sets up and infers configuration for later jobs                                              | Yes         |
| bazel-test-all            | dind-large, dfinity/ic-build     | CLOUD_CREDENTIALS_CONTENT, GPG_PASSPHRASE | On push to master/dev-gh-*, PRs (except hotfix-*), merge_group, workflow_dispatch, workflow_call, repository_dispatch           | Run all Bazel tests (with config for skipping long tests, etc.)                              | Yes / `/run-ci-main`         |
| bazel-build-fuzzers       | dind-large, dfinity/ic-build     | GPG_PASSPHRASE                        | Same as workflow triggers                                                                                   | Build fuzzers using Bazel with libfuzzer                                                     | Yes         |
| bazel-build-fuzzers-afl   | dind-large, dfinity/ic-build     | GPG_PASSPHRASE                        | Same as workflow triggers                                                                                   | Build fuzzers using Bazel with AFL                                                           | Yes         |
| python-ci-tests           | dind-small, dfinity/ic-build     | None                                  | Same as workflow triggers                                                                                   | Run Python CI tests (pytest)                                                                 | Yes         |
| build-ic                  | dind-small, dfinity/ic-build     | None                                  | On all triggers except merge_group                                                                          | Build the Internet Computer (IC) binaries, canisters and IC-OS                               | Yes         |
| build-determinism         | ubuntu-latest                    | None                                  | After build-ic and bazel-test-all complete                                                                 | Check for build determinism between cache and no-cache builds                                 | Yes         |
| cargo-clippy-linux        | dind-small, dfinity/ic-build     | None                                  | On PR/merge_group affecting Rust files, schedule, or workflow_dispatch                                      | Run Rust linter (clippy)                                                                     | Yes         |
| cargo-build-release-linux | dind-small, dfinity/ic-build     | None                                  | On PR/merge_group affecting Rust files, schedule, or workflow_dispatch                                      | Build Rust crates in release mode                                                            | Yes         |
| bazel-test-macos-intel    | macOS, dfinity/ic-build          | CLOUD_CREDENTIALS_CONTENT             | On protected branches, or with CI_MACOS_INTEL label, and only in dfinity/ic (public)                      | Run Bazel tests for macOS Intel builds                                                       | Yes / `/run-ci-main`         |
| bazel-build-arm64-linux| namespace-profile-arm64-linux, dfinity/ic-build | None                                                           | PR, merge_group, push (master, dev-gh-*)                   | Build pocket-ic-server                        | Yes         |
| bazel-test-macos-apple-silicon| namespace-profile-darwin, dfinity/ic-build | None                                                           | PR, merge_group, push (master, dev-gh-*)                   | Test targets with tag test_macos,test_macos_slow                        | Yes         |
| dependencies-check          | dind-small, dfinity/ic-build | GITHUB_TOKEN, JIRA_API_TOKEN, SLACK_PSEC_BOT_OAUTH_TOKEN       | On internal pull_request (not merge_group) and repository_dispatch              | Dependency scanning (Rust, Bazel, lock/toml changes)          | Yes / `/run-ci-main`       |

TODO: document other workflows.

## Using custom CI labels
Note that setting custom CI logic via the pull request title has been deprecated and we now use labels instead. See labels below for custom logic that can be enabled:

* `CI_ALL_BAZEL_TARGETS`: runs all bazel targets and uploads them to s3.
* `CI_OVERRIDE_DIDC_CHECK`: skips the backwards compatibility didc check.

Adding a label alone will not trigger CI, you will need to retrigger it by either opening & closing the PR or adding an empty commit with `git commit -m 'retrigger CI' --allow-empty`.

## Adding a new CI workflow
If your workflow is not complex, simply add the workflow to the `workflows` directory. See existing examples. If your workflow is more complex, see Generating CI yaml files below/

## Generating CI yaml files
Due to some limitations of GitHub Actions CI, we need to generate our own CI yaml files for our more complex pipelines. This is so we can use yaml anchors and re-use the same job setup. To add a new generated workflow:

1. Add your new workflow to `workflow-source`. Include any anchors you would like to use under the block `anchors`. If you name it something else, it will break.
1. Push your changes to GitHub which will trigger CI. This will automatically run a custom script (`generate-ci.py`) which will generate the full yaml file from your anchors, as well as delete the `anchors` block, as this will not work for github actions. This new yaml file will automatically be placed in the `workflows` directory.
1. Check that this new workflow file is correct.

## Using GitHub Apps in CI
Our CI contains several automated steps to either generate commits or PRs, usually for linting or version updates. Previously we used Personal Access Tokens generated by a service account to create a commit or PR with the correct permissions but we have now moved to GitHub apps. These have several benefits:
- they generate a token which is only valid while the workflow is running, enhancing security and removing the need for regular rotation
- they can be managed via the organization and do not require a separate service account
- they can be installed on mutliple repos, however they only have access to the repo they are installed in

## Automated PRs by Bots
To increase security and prevent a bot from accidentally changing files that it shouldn't, we are introducing a new config file stored in `.github/repo_policies/bot_approved_files.json` in all public repos where any files changed by a bot must be listed. If not, the workflow will fail and the PR can't be merged.

Workflow defined in: https://github.com/dfinity/public-workflows/blob/main/.github/workflows/repo_policies.yml
