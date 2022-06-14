import argparse
import os
import sys
import traceback
from pathlib import Path

from monpoly.monpoly import Monpoly
from pipeline.alert import AlertService
from pipeline.alert import DummyAlertService
from pipeline.artifact_manager import ArtifactManager
from pipeline.backend import file_io
from pipeline.backend.ci import Ci
from pipeline.backend.es import Es
from pipeline.backend.group import Group
from pipeline.mode import Mode
from pipeline.pipeline import Pipeline
from pipeline.pre_processor import UniversalPreProcessor
from util import docker
from util import env
from util.print import eprint


def main():
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
        help='The group name(s) for this Farm test run (search for "creating group" in Farm logs).',
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
        help="Which policies should be monitored",
    )
    parser.add_argument(
        "--list_policies",
        "-lp",
        action="store_true",
        default=False,
        help="List all supported policies (and exit)",
    )
    parser.add_argument(
        "--read", "-r", type=str, help="Rather than using ES API, read and load a log previously saved via `--mode raw`"
    )
    parser.add_argument("--gitlab_token", "-t", type=str, help="Gitlab token with read-api rights")
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
        "export IC_SLACK_POLICY_MONITORING_ALERTS_SERVICE)",
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
    args = parser.parse_args()

    # Detect meaningless option combinations
    if args.mainnet and args.group_names:
        print("Option --group_names should not be used together with --mainnet")
        exit(1)
    if args.mainnet and not args.limit_time:
        print("Option --limit_time should be specified together with --mainnet")
        exit(1)
    if args.limit_time and args.limit != 0:
        print("Option --limit_time requires setting --limit to 0")
        exit(1)

    if args.install_monpoly_docker_image:
        Monpoly.install_docker_image()
        exit(0)

    if args.list_policies:
        for formula in UniversalPreProcessor.get_supported_formulas():
            if UniversalPreProcessor.is_global_infra_required(set([formula])):
                print(f"{formula} (requires global infra)")
            else:
                print(f"{formula}")
        exit(0)

    # Read environment variables
    elasticsearch_endpoint = env.extract_value(args.elasticsearch_endpoint, "ELASTICSEARCH_ENDPOINT", secret=False)
    gitlab_token = env.extract_value(args.gitlab_token, "GITLAB_ACCESS_TOKEN")
    slack_token = env.extract_value(args.slack_service_id, "IC_SLACK_POLICY_MONITORING_ALERTS_SERVICE")
    liveness_slack_token = env.extract_value(
        args.slack_liveness_service_id, "IC_SLACK_POLICY_MONITORING_LIVENESS_SERVICE"
    )
    artifacts_location = env.extract_value_with_default(
        args.artifacts, "MONPOLY_PIPELINE_ARTIFACTS", default="./artifacts", secret=False
    )

    signature = env.generate_signature()

    def warn_no_slack(service_name: str, option: str) -> None:
        sys.stderr.write(f"WARNING: {service_name} is disabled; pass WebHook service ID via {option} to enable it.\n")

    if slack_token is None:
        warn_no_slack("Slack Alert Service", "--slack_service_id")
        slack = DummyAlertService(signature)
    else:
        slack = AlertService(slack_token, signature)

    if liveness_slack_token is None:
        warn_no_slack("Slack Liveness Service", "--liveness_slack_token")
        liveness_slack = DummyAlertService(signature)
    else:
        liveness_slack = AlertService(liveness_slack_token, signature)

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
        art_manager = ArtifactManager(project_root, Path(artifacts_location), signature)
        p = Pipeline(
            policies_path=str(project_root.joinpath("mfotl-policies")),
            art_manager=art_manager,
            modes=set(args.mode),
            alert_service=slack,
            liveness_channel=liveness_slack,
            docker=with_docker,
            docker_starter=docker_starter,
            formulas=set(args.policy) if args.policy else None,
        )

        # Obtains logs for each group
        if args.read:
            groups = file_io.read_logs(log_file=args.read)
        else:

            def report_es_endpoint(scenario: str, endpoint: str) -> None:
                eprint(f"Choosing {scenario} Elasticsearch endpoint for mainnet logs: {endpoint}")

            if not elasticsearch_endpoint and args.mainnet:
                es_url = "elasticsearch.mercury.dfinity.systems"
                report_es_endpoint("MAINNET", es_url)
            elif not elasticsearch_endpoint and not args.mainnet:
                es_url = "elasticsearch.testnet.dfinity.systems"
                report_es_endpoint("TESTNET", es_url)
            else:
                es_url = elasticsearch_endpoint
                report_es_endpoint("CUSTOM", es_url)

            if args.mainnet:
                es = Es(es_url, alert_service=slack, mainnet=True)
                gid = "mainnet"
                groups = {gid: Group(gid)}
            else:
                es = Es(es_url, alert_service=slack, mainnet=False)
                if args.group_names:
                    groups = {gid: Group(gid) for gid in args.group_names}
                else:
                    if gitlab_token is None:
                        print(
                            "Please specify at least one of the following options: --gitlab_token, --mainnet, --group_names"
                        )
                        exit(1)
                    ci = Ci(url="https://gitlab.com", project="dfinity-lab/public/ic", token=gitlab_token)
                    groups = ci.get_hourly_group_names()

            es.download_logs(groups, limit_per_group=args.limit, minutes_per_group=args.limit_time)

        p.run(groups)
        p.reproduce_all_violations()
        p.save_statistics()

    except Exception:
        trace = traceback.format_exc()
        error = "Policy monitoring pipeline stopped due to unhandled exception:\n```%s```" % trace
        sys.stderr.write(error + "\n")
        slack.alert(text=error)


if __name__ == "__main__":
    main()
