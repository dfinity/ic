#!/usr/bin/env python3
import argparse
import os
import sys
import traceback
from pathlib import Path
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import Optional
from typing import TypedDict

from monpoly.monpoly import Monpoly
from pipeline.alert import AlertService
from pipeline.alert import DummyAlertService
from pipeline.artifact_manager import ArtifactManager
from pipeline.backend.ci import Ci
from pipeline.backend.ci import CiException
from pipeline.backend.es import Es
from pipeline.backend.group import Group
from pipeline.backend.system_tests_artifact_manager import SystemTestsArtifactManager
from pipeline.global_infra import GlobalInfra
from pipeline.mode import Mode
from pipeline.pipeline import Pipeline
from pipeline.pre_processor import UniversalPreProcessor
from util import docker
from util import env


DEFAULT_MAINNET_ES_ENDPOINT = "elasticsearch.mercury.dfinity.systems"
DEFAULT_TESTNET_ES_ENDPOINT = "elasticsearch-v4.testnet.dfinity.systems"

LARGE_LOG_THRESHOLD = 1_073_741_824  # 1 GiB


def main():
    # === Phase I: Handle CLI arguments ===
    parser = argparse.ArgumentParser(
        description="Process streams of IC replica logs via MonPoly",
    )
    parser.add_argument(
        "--mainnet", "-mn", action="store_true", default=False, help="Download mainnet logs (rather than testnet)"
    )
    parser.add_argument(
        "--elasticsearch_endpoint",
        "-es",
        type=str,
        help='The Elasticsearch endpoint used to download the raw logs (e.g., "10.31.129.94:9200").',
    )
    parser.add_argument(
        "--group_names",
        "-g",
        type=str,
        nargs="*",
        help='The group name(s) for this system test run (search for "creating group" in system test logs).',
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=0,
        help="Maximal number of entries that will be downloaded from ES (0 = unlimited = default)",
    )
    parser.add_argument(
        "--limit_time",
        "-lt",
        type=int,
        help="Restricts the monitoring time window, per group, to [now - TIME_LIMIT min, now]",
    )
    parser.add_argument(
        "--mode",
        "-m",
        type=Mode,
        choices=list(Mode),
        default=[Mode.check_pipeline_liveness, Mode.universal_policy, Mode.save_event_stream, Mode.raw],
        nargs="+",
        help="Which mode(s) should be activated",
    )
    parser.add_argument(
        "--policy",
        "-p",
        type=str,
        nargs="+",
        help="Which policies should be monitored (must be a subset of --formulas_for_preproc, if the latter is specified)",
    )
    parser.add_argument(
        "--formulas_for_preproc",
        "-fpp",
        type=str,
        nargs="+",
        help="Events for which policies should be considered. If not specified, default taken from --policy",
    )
    parser.add_argument(
        "--list_policies",
        "-lp",
        action="store_true",
        default=False,
        help="List all supported policies (and exit)",
    )
    parser.add_argument(
        "--read",
        "-r",
        type=str,
        help="Rather than using ES API, read and load a log(s) previously saved via `--mode raw`. If a directory is specified, use all *.raw.log files inside as inputs. Very big inputs are supported. Input file names matching Gitlab CI jobs (e.g., hourly__workload_counter_canister_pot-2987404546.raw.log) will be used to automatically download registry snapshots (if specified policies require global infra); otherwise, you need to eplicityl pass --global_infra, or use --system_tests_working_dir instead of this option.",
    )
    parser.add_argument("--gitlab_token", "-t", type=str, help="Gitlab token with read-api rights")
    parser.add_argument(
        "--pre_master_pipeline",
        "-pmp",
        type=str,
        help="Specifies Gitlab pipeline ID for which pre-master system tests should be monitored",
    )
    parser.add_argument(
        "--system_tests_working_dir",
        "-w",
        type=str,
        help="Specifies path to a test driver's working_dir (used to extract group names and initial registry snapshots)",
    )
    parser.add_argument(
        "--download_working_dirs",
        "-dwd",
        action="store_true",
        default=True,
        help=("Save the the test driver's working_dirs that can be loaded via --system_tests_working_dir"),
    )
    parser.add_argument(
        "--fail",
        "-f",
        action="store_true",
        default=False,
        help="If an exception occurs, raise and fail rather than sending a Slack alert",
    )
    parser.add_argument(
        "--slack_service_id",
        "-s",
        type=str,
        help="Secret identifier of a Slack webhook service (alternatively, "
        "export IC_SLACK_POLICY_MONITORING_ALERTS_SERVICE)",
    )
    parser.add_argument(
        "--slack_liveness_service_id",
        "-sl",
        type=str,
        help="Secret identifier of a Slack webhook service for liveness "
        "indication (alternatively, "
        "export IC_SLACK_POLICY_MONITORING_LIVENESS_SERVICE)",
    )
    parser.add_argument(
        "--install_monpoly_docker_image",
        "-i",
        action="store_true",
        default=False,
        help="Ensure that the Monpoly Docker image is installed (and exit)",
    )
    parser.add_argument(
        "--without_docker", action="store_true", help="Whether to run Monpoly directly, *not* inside a Docker container"
    )
    # If we are inside a Docker instance, run Monpoly directly
    parser.set_defaults(without_docker=docker.is_inside_docker())
    parser.add_argument(
        "--artifacts",
        "-a",
        type=str,
        help="Directory in which the pipeline artifacts should be stored",
    )
    parser.add_argument(
        "--global_infra",
        "-gi",
        type=str,
        help=(
            "Path to a file containing a Global Infra snapshot; either internal YAML format (.yml or .yaml)"
            " or the ic-regedit's JSON (.json)"
        ),
    )
    parser.add_argument(
        "--git_revision",
        "-gr",
        type=str,
        default=None,
        help="The Git branch name or revision SHA of this pipeline invocation. Used to add policy definition links in violation alerts",
    )
    parser.add_argument(
        "--hard_timeout_seconds",
        "-hard",
        type=int,
        default=None,
        help="Hard timeout for the monitor process",
    )
    parser.add_argument(
        "--stop_at_first_violation",
        "-safv",
        action="store_true",
        default=True,
        help="Whether to replay the violations all found policy violations in batch mode after the pipeline finished",
    )
    parser.add_argument(
        "--replay_all_violations",
        "-rv",
        action="store_true",
        default=False,
        help="Whether to replay the violations all found policy violations in batch mode after the pipeline finished",
    )
    args = parser.parse_args()

    # Detect meaningless option combinations

    ModeConflictSpec = TypedDict(
        "ModeConflictSpec",
        {
            "modes": FrozenSet[str],
            "is_required": bool,
        },
    )
    CONFLICTING_MODES: Dict[str, ModeConflictSpec] = {
        "source_of_logs": {
            "modes": frozenset(["mainnet", "group_names", "pre_master_pipeline", "system_tests_working_dir"]),
            "is_required": True,
        },
        "test_driver_artifacts_locality": {
            "modes": frozenset(["system_tests_working_dir", "gitlab_token"]),
            "is_required": False,
        },
    }

    def activated_modes(category: str) -> FrozenSet[str]:
        return frozenset(filter(lambda x: vars(args)[x], CONFLICTING_MODES[category]["modes"]))

    for category, cmodes in CONFLICTING_MODES.items():
        if len(activated_modes(category)) > 1:
            conflicting_modes_disjunction = " or ".join(map(lambda x: f"--{x}", cmodes["modes"]))
            print(f"Only one of the options should be used at the same time: {conflicting_modes_disjunction}")
            exit(1)

    # TODO: specify the dependencies between CLI options via the above approach for conflicts
    if args.mainnet and not args.limit_time:
        print("Option --limit_time should be specified together with --mainnet")
        exit(1)
    if args.mainnet and not args.global_infra:
        print(
            "Warning: if you are monitoring policies that require Global Infra, "
            "then option --global_infra should be used together with --mainnet; see --list_policies"
        )
    if args.limit_time and args.limit != 0:
        print("Option --limit_time requires setting --limit to 0")
        exit(1)
    if args.download_working_dirs and not args.gitlab_token:
        print("Option --download_working_dirs requires specifying --gitlab_token")
        exit(1)

    if args.install_monpoly_docker_image:
        Monpoly.install_docker_image()
        exit(0)

    if args.list_policies:
        print("--- Supported events ---")
        preambles = set(UniversalPreProcessor.get_supported_preamble_events())
        for event in UniversalPreProcessor.get_supported_events():
            attrs = []
            if UniversalPreProcessor.is_event_dbg_level(event):
                attrs.append("requires DEBUG-level logs")
            if event in preambles:
                attrs.append("preamble event")
            if UniversalPreProcessor.is_global_infra_event(event):
                attrs.append("requires global infra")
            if len(attrs) > 0:
                attrs_str = " (" + "; ".join(attrs) + ")"
            else:
                attrs_str = ""
            print(f"{event}{attrs_str}")

        print("--- Supported IC policies ---")
        enabled_formulas = set(UniversalPreProcessor.get_enabled_formulas())
        for formula in UniversalPreProcessor.get_supported_formulas():
            attrs = []
            if formula not in enabled_formulas:
                attrs.append("DISABLED")
            if UniversalPreProcessor.is_dbg_log_level_required(formula):
                attrs.append("requires DEBUG-level logs")
            if UniversalPreProcessor.is_preamble_required(formula):
                attrs.append("needs preamble events")
            if UniversalPreProcessor.is_global_infra_required(set([formula])):
                attrs.append("requires global infra")
            if UniversalPreProcessor.is_end_event_required(formula):
                attrs.append("requires end event")
            if len(attrs) > 0:
                attrs_str = " (" + "; ".join(attrs) + ")"
            else:
                attrs_str = ""
            print(f"{formula}{attrs_str}")
        exit(0)

    # Read environment variables
    elasticsearch_endpoint = env.extract_value_with_default(
        args.elasticsearch_endpoint,
        "ELASTICSEARCH_ENDPOINT",
        default=(DEFAULT_MAINNET_ES_ENDPOINT if args.mainnet else DEFAULT_TESTNET_ES_ENDPOINT),
        secret=False,
    )
    gitlab_token = env.extract_value(args.gitlab_token, "GITLAB_ACCESS_TOKEN")
    slack_token = env.extract_value(args.slack_service_id, "IC_SLACK_POLICY_MONITORING_ALERTS_SERVICE")
    liveness_slack_token = env.extract_value(
        args.slack_liveness_service_id, "IC_SLACK_POLICY_MONITORING_LIVENESS_SERVICE"
    )
    artifacts_location = env.extract_value_with_default(
        args.artifacts, "MONPOLY_PIPELINE_ARTIFACTS", default="./artifacts", secret=False
    )
    git_revision = env.extract_value_with_default(
        args.git_revision, "MONPOLY_PIPELINE_GIT_REVISION", "master", secret=False
    )

    # === Phase II: Obtain the following objectgs: ===
    # . signature
    # . slack
    # . liveness_slack
    # . (optional) docker_starter
    # . project_root
    # . artifact_manager
    # . monpoly_pipeline
    # . groups
    signature = env.generate_signature()

    def warn_no_slack(service_name: str, option: str) -> None:
        sys.stderr.write(f"WARNING: {service_name} is disabled; pass WebHook service ID via {option} to enable it.\n")

    if slack_token is None:
        warn_no_slack("Slack Alert Service", "--slack_service_id")
        slack = DummyAlertService(signature, git_revision)
    else:
        slack = AlertService(slack_token, signature, git_revision)

    if liveness_slack_token is None:
        warn_no_slack("Slack Liveness Service", "--liveness_slack_token")
        liveness_slack = DummyAlertService(signature, git_revision)
    else:
        liveness_slack = AlertService(liveness_slack_token, signature, git_revision)

    # If the following env var is specified, the policy violation repros will
    #  be emitted as portable Docker commands, regardless of whether the
    #  original pipeline is run in a Docker instance.
    if "MONPOLY_PIPELINE_ARTIFACTS_ON_HOST" in os.environ:
        host_artifacts_dir = os.environ["MONPOLY_PIPELINE_ARTIFACTS_ON_HOST"]
        docker_starter = "\n".join(
            [
                f'TEMP_DIR=$(mktemp -p "$HOME" -d)'
                f' && echo "Downloading artifacts into $TEMP_DIR ..."'
                f' && rsync -r --rsync-path "sudo -u arshavir rsync"'
                f" -v {host_artifacts_dir}/{signature}"
                f' "$TEMP_DIR"'
                f" && docker image pull dfinity/monpoly_pipeline:latest"
                f" && docker run -it"
                f" --workdir /work/mfotl-policies --rm --entrypoint sh"
                f' -v "$TEMP_DIR/{signature}":/repro'
                f" dfinity/monpoly_pipeline:latest"
            ]
        )
    else:
        docker_starter = None

    project_root = Path(__file__).absolute().parent

    # The flag below indicates whether the pipeline should run Monpoly from
    #  within a Docker instance.
    with_docker = not args.without_docker

    try:
        gitlab: Optional[Ci]
        if gitlab_token is None:
            gitlab = None
        else:
            gitlab = Ci(url="https://gitlab.com", project="dfinity-lab/public/ic", token=gitlab_token, slack=slack)

        # Obtains logs for each group
        if args.read:
            raw_logs = Path(args.read)
            if raw_logs.is_dir():
                # Treat all *.raw.log files in this dir as inputs
                groups = {
                    group.name: group
                    for group in [
                        Group.fromFile(log_file=raw_log_file, as_stream=True)
                        for raw_log_file in raw_logs.iterdir()
                        if raw_log_file.is_file() and raw_log_file.suffixes == [".raw", ".log"]
                    ]
                }
                assert len(groups) > 0, f"no .raw.log files found at {args.read}"
                print(f"Created {len(groups)} groups from logs in {args.read}")
            else:
                assert raw_logs.is_file(), f"no such file or directory: {args.read}"
                group = Group.fromFile(
                    log_file=raw_logs,
                    as_stream=(raw_logs.stat().st_size >= LARGE_LOG_THRESHOLD),
                )
                groups = {group.name: group}
        else:
            if args.mainnet:
                es = Es(elasticsearch_endpoint, alert_service=slack, mainnet=True, fail=args.fail)
                group_name = "mainnet"
                groups = {group_name: Group(group_name)}
            else:
                es = Es(elasticsearch_endpoint, alert_service=slack, mainnet=False, fail=args.fail)
                if args.group_names:
                    assert isinstance(args.group_names, Iterable)
                    group_names: Iterable[str] = args.group_names
                    if (
                        any([Group.is_group_name_local(g) for g in group_names])
                        and args.system_tests_working_dir is None
                    ):
                        print("please specify --system_tests_working_dir to monitor locally invoked tests")
                        exit(1)
                    groups = {g: Group(g) for g in group_names}
                else:
                    if gitlab_token is not None:
                        if args.pre_master_pipeline:
                            # Monitor all system tests from the pre-master pipeline with ID args.pre_master_pipeline
                            groups = gitlab.get_premaster_groups_for_pipeline(
                                args.pre_master_pipeline, include_pattern=None
                            )
                        else:
                            # Monitor all system tests from the regular pipelines (hourly, nightly)
                            groups = gitlab.get_regular_groups()
                            # Keep at most two instances of the same pot
                            pots: Dict[str, int] = dict()
                            fitered_groups: Dict[str, Group] = dict()
                            for gname, group in groups.items():
                                pot_name = group.pot_name()
                                if pot_name not in pots:
                                    pots[pot_name] = 1
                                else:
                                    pots[pot_name] += 1
                                if pots[pot_name] <= 3:
                                    print(f"Keeping instance #{pots[pot_name]} of {pot_name}")
                                    fitered_groups[gname] = group
                                else:
                                    print(f"Removing instance #{pots[pot_name]} of {pot_name}")
                            groups = fitered_groups

                    elif args.system_tests_working_dir is not None:
                        # Relying upon args.system_tests_working_dir, e.g., for end-to-end testing the pipeline implementation
                        groups = Ci.get_groups_from_systest_logs(
                            SystemTestsArtifactManager(args.system_tests_working_dir).test_driver_log_path()
                        )
                    else:
                        print(
                            f"Please specify at least one of the following options: {CONFLICTING_MODES['source_of_logs']}"
                        )
                        exit(1)

            es.download_logs(groups, limit_per_group=args.limit, minutes_per_group=args.limit_time)

        # === Obtain GlobalInfra ===
        policies = set(args.policy) if args.policy else None
        formulas_for_preproc = set(args.formulas_for_preproc) if args.formulas_for_preproc else policies
        assert not (isinstance(policies, set) and isinstance(formulas_for_preproc, set)) or policies.issubset(
            formulas_for_preproc
        )

        if args.global_infra:
            # Load global infra from file (same for all groups)
            print(f"Setting global infra for all groups based on {args.global_infra}")
            gi_path = Path(args.global_infra)
            suf = gi_path.suffix
            if suf in [".yml", ".yaml"]:
                infra = GlobalInfra.fromYamlFile(gi_path)
            elif suf == ".json":
                infra = GlobalInfra.fromIcRegeditSnapshotFile(gi_path)
            else:
                raise Exception(f"unsupported file format: {suf}")
            for group in groups.values():
                group.global_infra = infra
        elif UniversalPreProcessor.is_global_infra_required(formulas_for_preproc):
            for group in groups.values():
                print(f"Setting global infra for {str(group)}")
                if args.system_tests_working_dir:
                    # Extract Global Infra from an initial registry snapshot file
                    group.global_infra = GlobalInfra.fromIcRegeditSnapshotFile(
                        SystemTestsArtifactManager(args.system_tests_working_dir).registry_snapshot_path(
                            group.pot_name()
                        )
                    )
                else:
                    # Obtain Global Infra from initial registry snapshot GitLab artifact
                    assert gitlab is not None, "Need to specify --global_infra or --gitlab_token"
                    try:
                        snap_bulb = gitlab.get_registry_snapshot_for_group(group)
                        group.global_infra = GlobalInfra.fromIcRegeditSnapshotBulb(snap_bulb, source=group.job_url())
                    except CiException:
                        print("Falling back to inferring Global Infra from logs ...")
                        # logs need to be reusable, so we serialize the stream
                        group.logs = list(group.logs)
                        group.infer_global_infra()
        else:
            print("Skipping Global Infra")

        art_manager = ArtifactManager(project_root, Path(artifacts_location), signature)

        if args.download_working_dirs:
            for group in groups.values():
                dest_path = art_manager.working_dir_path(group)
                gitlab.get_artifacts_for_group(group, dest_path)

        # === Phase III: Run the pipeline ===
        monpoly_pipeline = Pipeline(
            policies_path=str(project_root.joinpath("mfotl-policies")),
            art_manager=art_manager,
            modes=set(args.mode),
            alert_service=slack,
            liveness_channel=liveness_slack,
            docker=with_docker,
            docker_starter=docker_starter,
            git_revision=git_revision,
            formulas_for_preproc=formulas_for_preproc,
            policies_to_monitor=policies,
            fail=args.fail,
            hard_timeout=float(args.hard_timeout_seconds) if args.hard_timeout_seconds else None,
            stop_at_first_violation=args.stop_at_first_violation,
        )
        monpoly_pipeline.run(groups)
        if args.replay_all_violations:
            monpoly_pipeline.reproduce_all_violations()
        monpoly_pipeline.save_statistics()

    except Exception as e:
        if args.fail:
            raise e
        trace = traceback.format_exc()
        error = "Policy monitoring pipeline stopped due to unhandled exception:\n```%s```" % trace
        sys.stderr.write(error + "\n")
        slack.alert(text=error)


if __name__ == "__main__":
    main()
