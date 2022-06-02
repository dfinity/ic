import argparse
import os
import sys
import traceback

from monpoly.monpoly import Monpoly
from pipeline.alert import AlertService
from pipeline.ci import Ci
from pipeline.ci import Group
from pipeline.mode import Mode
from pipeline.pipeline import Pipeline
from pipeline.pre_processor import UniversalPreProcessor
from util import docker


def main():
    parser = argparse.ArgumentParser(
        description="Process streams of IC replica logs via MonPoly",
    )
    parser.add_argument(
        "--group_ids",
        "-g",
        type=str,
        nargs="*",
        help='The group name(s) for this Farm test run (search for "creating group" in Farm logs).',
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=1_000,
        help="Maximal number of entries that will be downloaded from ES (0 = unlimited)",
    )
    parser.add_argument(
        "--mode",
        "-m",
        type=Mode,
        choices=list(Mode),
        default=[Mode.universal_policy],
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
        default="artifacts",
        help="Directory in which the pipeline artifacts should be stored",
    )
    args = parser.parse_args()

    if args.install_monpoly_docker_image:
        Monpoly.install_docker_image()
        exit(0)

    if args.list_policies:
        for formula in UniversalPreProcessor.get_supported_formulas():
            rgi = UniversalPreProcessor.is_global_infra_required(set([formula]))
            print(f"{formula}{' (requires global infra)' if rgi else ''}")
        exit(0)

    if args.slack_service_id:
        slack = AlertService(args.slack_service_id)
    else:
        slack = AlertService(os.environ["IC_SLACK_POLICY_MONITORING_ALERTS_SERVICE"])

    if args.slack_liveness_service_id:
        liveness_slack = AlertService(args.slack_liveness_service_id, signature=slack.signature)
    else:
        liveness_slack = AlertService(
            os.environ["IC_SLACK_POLICY_MONITORING_LIVENESS_SERVICE"], signature=slack.signature
        )

    # The flag below indicates whether the pipeline should run Monpoly from
    #  within a Docker instance.
    with_docker = not args.without_docker

    # If the following env var is specified, the policy violation repros will
    #  be emitted as portable Docker commands, regardless of whether the
    #  original pipeline is run in a Docker instance.
    if "MONPOLY_PIPELINE_ARTIFACTS_ON_HOST" in os.environ:
        host_artifacts_dir = os.environ["MONPOLY_PIPELINE_ARTIFACTS_ON_HOST"]
        docker_starter = "\n".join(
            [
                f'TEMP_DIR=$(mktemp -p "$HOME" -d)'
                f' && echo "Downloading artifacts into $TEMP_DIR ..."'
                f" && rsync -r"
                f" -v {host_artifacts_dir}/{slack.signature}"
                f' "$TEMP_DIR"'
                f" && docker image pull aterga/monpoly_pipeline:latest"
                f" && docker run -it"
                f" --workdir /work/mfotl-policies --rm --entrypoint sh"
                f' -v "$TEMP_DIR/{slack.signature}":/repro'
                f" aterga/monpoly_pipeline:latest"
            ]
        )
    else:
        docker_starter = None

    try:
        p = Pipeline(
            modes=set(args.mode),
            alert_service=slack,
            liveness_channel=liveness_slack,
            docker=with_docker,
            docker_starter=docker_starter,
            limit=args.limit,
            artifacts_location=args.artifacts,
            formulas=set(args.policy) if args.policy else None,
        )

        # Get group names
        if args.read:
            groups = p.read_logs(log_file=args.read)
        else:
            if args.group_ids:
                groups = {gid: Group(gid, url="Omitted interaction with GitLab CI") for gid in args.group_ids}
            else:
                ci = Ci(url="https://gitlab.com", project="dfinity-lab/public/ic", token=args.gitlab_token)
                groups = ci.get_hourly_group_ids()
            p.download_logs(groups)

        p.ensure_file_structure()

        p.run(groups)
        p.run_all_repros()
        p.save_stat()

    except Exception:
        trace = traceback.format_exc()
        error = "Policy monitoring pipeline stopped due to unhandled exception:\n```%s```" % trace
        sys.stderr.write(error + "\n")
        slack.alert(text=error, with_url=True)


if __name__ == "__main__":
    main()
