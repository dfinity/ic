# Dependency Submission Job

## Purpose

The dependency submission job parses the Bazel-managed Rust dependency lock file
(`Cargo.Bazel.toml.lock`) and submits the resolved dependency graph to GitHub via
the [Dependency submission REST API][gh-dep-submission]. Once submitted, the
dependencies show up in the repository's
[dependency graph][gh-dep-graph], which in turn powers
[Dependabot alerts][gh-dependabot] and the
[`dependency-review-action`][gh-dep-review] used by the
[`security-checks.yml`](#security-checksyml-pull-requests) workflow.

In short: this job is how the IC repo's Rust crate dependencies become visible to
GitHub's vulnerability tooling.

[gh-dep-submission]: https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
[gh-dep-graph]: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph
[gh-dependabot]: https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
[gh-dep-review]: https://github.com/actions/dependency-review-action

## Entry point

[`job/bazel_rust_gh_submission_job.py`](../job/bazel_rust_gh_submission_job.py)

The entry point is intentionally tiny:

1. It determines the base directory that contains the lock file:
   - `GITHUB_PR_DIR` if set (used by the PR workflow to point at the PR checkout
     while running from the base-branch checkout), otherwise
   - `GITHUB_WORKSPACE` (the default checkout directory).
2. It calls `GithubApi.submit_dependencies([(basedir, "Cargo.Bazel.toml.lock")])`.

## How it works

```
Cargo.Bazel.toml.lock
        │
        ▼
parser/bazel_toml_parser.py        parse_bazel_toml_to_gh_manifest()
        │   resolves every package + its dependencies into a
        │   GitHub "manifest" of pkg:cargo/<name>@<version> entries
        ▼
integration/github/github_dependency_submission.py   (dataclasses for the
        │   GitHub snapshot payload: detector, job, manifests, ...)
        ▼
integration/github/github_api.py   GithubApi.submit_dependencies()
        │   builds the snapshot request and POSTs it to
        │   /repos/{owner}/{repo}/dependency-graph/snapshots
        ▼
GitHub dependency graph
```

Key implementation details:

- **Parsing** ([`parser/bazel_toml_parser.py`](../parser/bazel_toml_parser.py)):
  `parse_bazel_toml_to_gh_manifest` reads the TOML lock file and emits a
  `GHSubManifest` of resolved `pkg:cargo/<name>@<version>` package URLs. Direct
  dependencies in the lock file may be written as either `"<name>"` or
  `"<name> <version>"`, so packages are scanned twice to build lookup maps before
  the dependency references are resolved. Ambiguous or missing references raise a
  `RuntimeError`.
- **Submission** ([`integration/github/github_api.py`](../integration/github/github_api.py)):
  `submit_dependencies` assembles a `GHSubRequest` (detector
  `bazel-rust-detector`, correlator
  `Bazel Dependency Submission / bazel-dependency-submission`) and POSTs the
  JSON snapshot. The call is retried up to 6 times with exponential backoff and
  only treats HTTP `201` as success.

## Required environment

| Variable | Required | Description |
| --- | --- | --- |
| `GITHUB_TOKEN` | yes | Token used to authenticate the snapshot POST. If unset the job raises. |
| `GITHUB_REPOSITORY` | yes | `owner/repo` used to build the snapshot URL. |
| `GITHUB_RUN_ID` | yes | Used as the submission job id. |
| `GITHUB_REF` | yes | Git ref recorded on the snapshot. |
| `GITHUB_SHA` / `GITHUB_PR_SHA` | yes | Commit recorded on the snapshot (`GITHUB_PR_SHA` wins if set). |
| `GITHUB_WORKSPACE` / `GITHUB_PR_DIR` | yes | Directory containing `Cargo.Bazel.toml.lock` (`GITHUB_PR_DIR` wins if set). |

## CI jobs that use this job

### `bazel-dependency-submission.yml` (push to master)

[`.github/workflows/bazel-dependency-submission.yml`](../../../../.github/workflows/bazel-dependency-submission.yml)

- **Trigger:** every push to `master`.
- **What it does:** checks out the repo, installs `requirements.txt`, and runs
  `job/bazel_rust_gh_submission_job.py` with `GITHUB_WORKSPACE` as the base
  directory. This keeps the dependency graph on `master` up to date so Dependabot
  has an accurate baseline.
- **Permissions:** `contents: write` (required to write the snapshot).

### `security-checks.yml` (pull requests)

[`.github/workflows/security-checks.yml`](../../../../.github/workflows/security-checks.yml)

- **Trigger:** `pull_request_target`.
- **What it does:**
  1. Checks out the base branch (`master`) into `base/` and the PR head into
     `pr/` (sparse checkout of just `Cargo.Bazel.toml.lock`).
  2. Runs `job/bazel_rust_gh_submission_job.py` from the `base/` checkout but with
     `GITHUB_PR_DIR` pointing at the `pr/` checkout, so the **PR's** lock file is
     submitted as a snapshot for the PR's head commit.
  3. Runs [`actions/dependency-review-action`][gh-dep-review] with
     `fail-on-severity: moderate`, which compares the submitted snapshot against
     the base and fails the PR if it introduces dependencies with known
     vulnerabilities of moderate severity or higher.
- **Permissions:** `contents: write`.

> Note: this workflow uses `pull_request_target`, so it runs trusted code from
> the base branch with access to secrets while only the PR's lock file is checked
> out into `pr/`.

## Related files

- [`job/bazel_rust_gh_submission_job.py`](../job/bazel_rust_gh_submission_job.py) — entry point.
- [`parser/bazel_toml_parser.py`](../parser/bazel_toml_parser.py) — lock-file parser.
- [`integration/github/github_dependency_submission.py`](../integration/github/github_dependency_submission.py) — snapshot payload dataclasses.
- [`integration/github/github_api.py`](../integration/github/github_api.py) — `submit_dependencies` implementation.
