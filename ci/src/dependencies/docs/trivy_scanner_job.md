# Trivy Container Scanner Job

## Purpose

The Trivy scanner job periodically scans the IC OS container image(s) for
vulnerable OS packages, vulnerable binaries, and leaked secrets using
[Trivy][trivy]. Each finding is tracked as a Jira ticket (so it can be
risk-assessed and tracked to resolution) and surfaced to the responsible team
via Slack. Findings that can't be represented in Jira are handled by a Slack
failover data store instead.

This is the nightly "are there known vulnerabilities in the image we ship?"
check, as opposed to the [dependency submission job](dependency_submission_job.md)
which feeds GitHub's dependency graph for Rust crates.

[trivy]: https://github.com/aquasecurity/trivy

## Entry point

[`job/bazel_trivy_container_ic_scanner_periodic_job.py`](../job/bazel_trivy_container_ic_scanner_periodic_job.py)

The `main()` function wires together the moving parts and runs a periodic scan:

1. Builds a [`NotificationConfig`](../notification/notification_config.py) that
   enables notifications for:
   - findings that need a risk assessment,
   - findings for which a patched version is available,
   - deleted findings,
   - scan job succeeded / failed (only for the `PERIODIC_SCAN` job type),
   and registers two Slack notification handlers
   ([`SlackTrivyFindingNotificationHandler`](../integration/slack/slack_trivy_finding_notification_handler.py)
   and [`SlackDefaultNotificationHandler`](../integration/slack/slack_default_notification_handler.py)).
2. Constructs a [`DependencyScanner`](../scanner/dependency_scanner.py) from:
   - [`BazelTrivyContainer`](../scanner/manager/bazel_trivy_dependency_manager.py) — the dependency manager that actually runs Trivy and parses its output,
   - [`JiraFindingDataSource`](../data_source/jira_finding_data_source.py) — persists findings as Jira tickets,
   - the notifier as the scanner subscriber,
   - [`SlackFindingsFailoverDataStore`](../data_source/slack_findings_failover_data_store.py) — handles findings that can't be stored in Jira.
3. Calls `scanner_job.do_periodic_scan(REPOS_TO_SCAN)`.

The set of images to scan is configured in
[`config/bazel_trivy_periodic.py`](../config/bazel_trivy_periodic.py)
(`REPOS_TO_SCAN`). Today it scans the GuestOS prod image
(`ic-os/guestos/envs/prod`), owned by the Node team.

## How it works

```
config/bazel_trivy_periodic.py  REPOS_TO_SCAN (image projects + owning teams)
        │
        ▼
scanner/dependency_scanner.py   DependencyScanner.do_periodic_scan()
        │   for each project:
        ▼
scanner/manager/bazel_trivy_dependency_manager.py   BazelTrivyContainer.get_findings()
        │   runs `bazel run vuln-scan -- --format json ...`
        │   (the vuln-scan target is defined in ic-os/defs.bzl and backed by
        │    ic-os/vuln-scan/vuln-scan.sh, which untars the rootfs and runs trivy)
        │   parses the JSON results into Finding objects via three parsers:
        │     - OSPackageTrivyResultParser  (os-pkgs)
        │     - BinaryTrivyResultParser     (lang-pkgs / *binary)
        │     - SecretTrivyResultParser     (secret)
        ▼
        │   reconcile findings against existing ones:
        ├─► data_source/jira_finding_data_source.py        create/update/delete Jira tickets
        ├─► data_source/slack_findings_failover_data_store.py  findings not representable in Jira
        └─► notification/notification_creator.py           Slack notifications
                                                            (risk assessment needed,
                                                             patch available, deleted,
                                                             job succeeded/failed)
```

Key implementation details:

- **Running Trivy**
  ([`TrivyExecutor.run_trivy_and_parse_data`](../scanner/manager/bazel_trivy_dependency_manager.py)):
  invokes `bazel run vuln-scan -- --output-path <findings.json> --format json
  --hash-output-path <file-hashes.txt>`. The `vuln-scan` Bazel target is generated
  per image in [`ic-os/defs.bzl`](../../../../ic-os/defs.bzl) and runs
  [`ic-os/vuln-scan/vuln-scan.sh`](../../../../ic-os/vuln-scan/vuln-scan.sh),
  which untars the image rootfs and runs `trivy rootfs` over it. Trivy ships its
  vulnerability DB over ghcr.io, which is frequently rate limited, so the scan is
  retried up to `TRIVY_SCAN_RETRIES` (10) times when the output file is missing or
  empty.
- **Parsing** ([`BazelTrivyContainer.get_findings`](../scanner/manager/bazel_trivy_dependency_manager.py)):
  each Trivy result is routed to one of three parsers based on its `Class`/`Type`.
  OS packages with the same set of vulnerabilities are grouped into a single
  finding; binaries become a single finding with their vulnerable sub-packages as
  first-level dependencies; secrets each become a finding. Results that no parser
  can handle produce a warning and an app-owner notification.
- **Reconciliation** ([`DependencyScanner.do_periodic_scan`](../scanner/dependency_scanner.py)):
  current findings are merged with the open findings already in Jira — existing
  tickets get their vulnerabilities/dependencies/owning-teams/score updated (risk
  is cleared when new vulnerabilities appear), brand-new findings are created and
  linked to related/previously-deleted findings, and findings that no longer
  appear are deleted. Failures per repository are reported via
  `on_scan_job_failed`.
- **Jira vs. Slack failover store**
  ([`SlackFindingsFailoverDataStore.can_handle`](../data_source/slack_findings_failover_data_store.py)):
  most findings are stored in Jira as **one ticket per vulnerable dependency**,
  listing all of that dependency's vulnerabilities. A few dependencies, however,
  have so many vulnerabilities that the full list does not fit into a single Jira
  ticket. For those, the findings are routed to the Slack failover store instead,
  which stores a **separate entry per vulnerability**. A finding is sent to the
  failover store when its vulnerable dependency id starts with one of the prefixes
  configured in `FAILOVER_FINDING_PREFIXES` in
  [`data_source/slack_findings_failover_data_store.py`](../data_source/slack_findings_failover_data_store.py)
  (currently `linux-libc-dev` and `linux-modules` for the `ic` repo /
  `BAZEL_TRIVY_CS` scanner). When a finding is handled by the failover store, any
  pre-existing Jira ticket for it is deleted to avoid duplication.
- **Triggering a base-image bump when a patch is available**
  ([`GithubTrivyFindingNotificationHandler`](../integration/github/github_trivy_finding_notification_handler.py)):
  when the scan detects that a **new patch version** has become available for an
  OS-package finding, the
  [`container-base-images.yml`](../../../../.github/workflows/container-base-images.yml)
  workflow is invoked (via a `workflow_dispatch` on `master`) to rebuild and bump
  the base container images so the patched package version is picked up. This is
  wired through the Slack notification handler — when a finding has a patch
  version available, the Slack message notes that a base image rebuild was
  triggered and the GitHub handler dispatches the workflow. The workflow is only
  dispatched **once per scan job** (guarded by `pipeline_run`), regardless of how
  many findings have patches available. On `master`,
  `container-base-images.yml` pushes the rebuilt images to DockerHub and updates
  the image references via an automated PR.

## Required environment

| Variable | Required | Description |
| --- | --- | --- |
| `GITHUB_TOKEN` | yes | Used by the GitHub integration. |
| `JIRA_API_TOKEN` | yes | Used by `JiraFindingDataSource` to create/update tickets. |
| `SLACK_PSEC_BOT_OAUTH_TOKEN` | yes | Used by the Slack notification handlers / failover store. |
| `REPO_NAME` | yes | `owner/repo`, used to build PR / CI pipeline links in notifications. |
| `CI_PIPELINE_ID` | recommended | Recorded as the scan job id (defaults to a placeholder otherwise). |
| `LOG_LEVEL` | optional | Logging verbosity (e.g. `INFO`). |

## CI jobs that use this job

### `container-scan-nightly.yml` (scheduled / manual)

[`.github/workflows/container-scan-nightly.yml`](../../../../.github/workflows/container-scan-nightly.yml)

- **Trigger:** scheduled nightly (`cron: "0 1 * * *"`) and `workflow_dispatch`.
- **Runner / container:** runs inside the `ic-build` container on a `dind-large`,
  privileged runner (Bazel + Trivy need to build/untar the image), with a 60
  minute timeout and the `dependency-scan` environment (which holds the secrets).
- **What it does:** installs `requirements.txt`, sets
  `PYTHONPATH=ci/src:ci/src/dependencies`, then runs
  `job/bazel_trivy_container_ic_scanner_periodic_job.py` from
  `ci/src/dependencies/`. Secrets (`GITHUB_TOKEN`, `JIRA_API_TOKEN`,
  `SLACK_PSEC_BOT_OAUTH_TOKEN`) are provided as env vars.

## Related files

- [`job/bazel_trivy_container_ic_scanner_periodic_job.py`](../job/bazel_trivy_container_ic_scanner_periodic_job.py) — entry point.
- [`config/bazel_trivy_periodic.py`](../config/bazel_trivy_periodic.py) — images to scan.
- [`scanner/dependency_scanner.py`](../scanner/dependency_scanner.py) — generic scan orchestration / reconciliation.
- [`scanner/manager/bazel_trivy_dependency_manager.py`](../scanner/manager/bazel_trivy_dependency_manager.py) — Trivy runner + result parsers.
- [`data_source/jira_finding_data_source.py`](../data_source/jira_finding_data_source.py) — Jira ticket storage.
- [`data_source/slack_findings_failover_data_store.py`](../data_source/slack_findings_failover_data_store.py) — Slack failover storage.
- [`notification/notification_creator.py`](../notification/notification_creator.py) and [`notification/notification_config.py`](../notification/notification_config.py) — notification wiring.
- [`integration/slack/slack_trivy_finding_notification_handler.py`](../integration/slack/slack_trivy_finding_notification_handler.py) — Slack finding notifications; delegates the patch-available case to the GitHub handler.
- [`integration/github/github_trivy_finding_notification_handler.py`](../integration/github/github_trivy_finding_notification_handler.py) and [`integration/github/github_workflow_config.py`](../integration/github/github_workflow_config.py) — dispatch of `container-base-images.yml` on patch availability.
- [`.github/workflows/container-base-images.yml`](../../../../.github/workflows/container-base-images.yml) — rebuilds / bumps the base container images.
- [`ic-os/vuln-scan/vuln-scan.sh`](../../../../ic-os/vuln-scan/vuln-scan.sh) and [`ic-os/defs.bzl`](../../../../ic-os/defs.bzl) — the `vuln-scan` Bazel target.
