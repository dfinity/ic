# Dependency Management & Vulnerability Scanning

This directory contains the Python tooling that the IC repository uses to track
its dependencies and scan them for known vulnerabilities. The tooling runs from
GitHub Actions workflows (see [`.github/workflows`](../../../.github/workflows))
and reports findings to GitHub, Jira, and Slack.

## Overview

There are two independent jobs, each documented in detail under [`docs/`](docs):

| Job | What it does | Entry point | Documentation |
| --- | --- | --- | --- |
| **Dependency submission** | Parses the Rust Bazel lock file (`Cargo.Bazel.toml.lock`) and submits the resolved dependency graph to GitHub, feeding Dependabot alerts and the PR dependency-review check. | [`job/bazel_rust_gh_submission_job.py`](job/bazel_rust_gh_submission_job.py) | [docs/dependency_submission_job.md](docs/dependency_submission_job.md) |
| **Trivy container scanner** | Periodically scans the IC OS container image(s) with Trivy for vulnerable OS packages, vulnerable binaries, and leaked secrets, tracking each finding in Jira and notifying owners via Slack. | [`job/bazel_trivy_container_ic_scanner_periodic_job.py`](job/bazel_trivy_container_ic_scanner_periodic_job.py) | [docs/trivy_scanner_job.md](docs/trivy_scanner_job.md) |

The two jobs are complementary:

- the **dependency submission** job covers the repo's **Rust crate** dependencies
  and routes findings through GitHub's native supply-chain tooling;
- the **Trivy** job covers what is actually **baked into the shipped container
  image** (OS packages, binaries, secrets) and routes findings through Jira and
  Slack.

## CI jobs at a glance

| Workflow / action | Trigger | Runs |
| --- | --- | --- |
| [`bazel-dependency-submission.yml`](../../../.github/workflows/bazel-dependency-submission.yml) | push to `master` | dependency submission job |
| [`security-checks.yml`](../../../.github/workflows/security-checks.yml) | `pull_request_target` | dependency submission job (PR lock file) + `dependency-review-action` |
| [`container-scan-nightly.yml`](../../../.github/workflows/container-scan-nightly.yml) | nightly cron + `workflow_dispatch` | Trivy container scanner job |

See the per-job docs for triggers, required environment variables, and the full
data flow.

## Directory layout

| Path | Contents |
| --- | --- |
| [`job/`](job) | Job entry points (run from CI). |
| [`config/`](config) | Static configuration, e.g. which images the Trivy job scans. |
| [`scanner/`](scanner) | Generic scan orchestration and the Trivy dependency manager + result parsers. |
| [`parser/`](parser) | `Cargo.Bazel.toml.lock` → GitHub manifest parser used by the submission job. |
| [`data_source/`](data_source) | Finding persistence (Jira) and the Slack failover store. |
| [`integration/`](integration) | GitHub and Slack API integrations. |
| [`notification/`](notification) | Notification configuration and dispatch. |
| [`model/`](model) | Shared domain types (`Finding`, `Dependency`, `Project`, `Team`, ...). |
| [`docs/`](docs) | Per-job documentation (see table above). |

## Running locally

Both jobs expect `PYTHONPATH` to include `ci/src` and `ci/src/dependencies` and
the packages in [`requirements.txt`](requirements.txt) to be installed. They also
require the credentials listed in each job's documentation (GitHub token, and for
the Trivy job a Jira token and a Slack bot token). Refer to the workflow files and
the per-job docs for the exact environment.
