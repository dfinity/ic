import re
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from monpoly.monpoly import AlertHandlerParams
from monpoly.monpoly import ErrorHandlerParams
from monpoly.monpoly import ExitHandlerParams
from monpoly.monpoly import Monpoly
from monpoly.monpoly import MonpolyException
from monpoly.monpoly import MonpolyGlobalTimeout
from monpoly.monpoly import MonpolyIoClosed
from monpoly.multi_monitor import MultiMonitor
from util.print import eprint

from .alert import AlertService
from .artifact_manager import ArtifactManager
from .backend.group import Group
from .formula_manager import formula_local_path
from .mode import Mode
from .pre_processor import PreProcessor
from .pre_processor import UniversalPreProcessor
from .repro_manager import ReproManager


def gurl(group: Group) -> str:
    url = group.job_url()
    if url:
        return url
    return "<not available>"


def furl(git_rev: str, formula: str) -> str:
    return f"<https://sourcegraph.com/github.com/dfinity/ic@{git_rev}/-/blob/policy-monitoring/mfotl-policies/{formula}/formula.mfotl|{formula}>"


class Pipeline:
    def __init__(
        self,
        policies_path: str,
        art_manager: ArtifactManager,
        modes: Set[Mode],
        alert_service: AlertService,
        liveness_channel: AlertService,
        docker: bool,
        docker_starter: Optional[str] = None,  # only used in alerts with repros
        git_revision: str = "master",  # the Git sha of this pipeline invocation
        formulas_for_preproc: Optional[Set[str]] = None,
        policies_to_monitor: Optional[Set[str]] = None,
        fail=False,  # if True, raise exceptions instead of just sending Slack alerts
        hard_timeout: Optional[float] = None,  # in seconds
        stop_at_first_violation=True,
    ):
        self.policies_path = policies_path
        self.art_manager = art_manager
        self.slack = alert_service
        self.liveness_channel = liveness_channel
        self.docker = docker
        self.docker_starter = docker_starter
        self.git_revision = git_revision
        self.modes = modes

        self.stat: Dict[str, Dict] = dict()

        # maps group names to formula to set of repro cmds
        self.repros: Dict[str, Dict[str, Set[Tuple[str, ...]]]] = dict()

        # maps formula to tuple of variable names
        self.var_seq: Dict[str, Tuple[str, ...]] = dict()

        self.formulas_for_preproc = formulas_for_preproc
        if policies_to_monitor:
            self.policies_to_monitor = sorted(policies_to_monitor)
        else:
            self.policies_to_monitor = UniversalPreProcessor.get_enabled_formulas()

        self.fail = fail
        self.hard_timeout = hard_timeout
        self.stop_at_first_violation = stop_at_first_violation

    def check_pipeline_alive(self, group: Group, pproc: PreProcessor, event_stream: Iterable[str]) -> None:

        formula = "dummy"

        log_file = self.art_manager.event_stream_file(group, pproc.name)

        found_expected_violation = False

        def stdout_handler(arg: AlertHandlerParams) -> None:
            nonlocal found_expected_violation
            found_expected_violation = True

        def repro(session: Monpoly, docker_starter=self.docker_starter, log_file=log_file) -> str:
            if docker_starter is not None:
                repro_cmd = session.cmd_wo_rss(enforce_no_docker=True) + ("-log", f'"/repro/{log_file.name}"')
                res = " ".join(repro_cmd)
                return "\n".join([docker_starter, res])
            else:
                repro_cmd = session.cmd_wo_rss() + ("-log", f'"/repro/{log_file.name}"')
                res = " ".join(repro_cmd)
                return res

        with Monpoly(
            name=f"{log_file.stem}.{formula}",
            docker=self.docker,
            workdir=self.policies_path,
            reprodir=str(self.art_manager.artifacts_prefix()),
            local_sig_file="predicates.sig",
            local_formula=str(formula_local_path(formula)),
            hard_timeout=60.0,
            alert_handler=stdout_handler,
            error_handler=lambda _: None,
            exit_handler=lambda _: None,
        ) as monitor:
            try:
                for datum in event_stream:
                    monitor.submit(datum)
            except MonpolyIoClosed:
                # Monpoly closes STDIN after the first violation if
                # the -stop_at_first_viol flag is set
                pass
            except MonpolyException:
                pass

        if found_expected_violation:
            self.liveness_channel.alert(
                level="✅🍏✅🍏✅🍏✅",
                text=(
                    f"Policy monitoring pipeline status: operational (see reports in #ic-policy-alerts)\n"
                    f"Repro:\n"
                    f"```\n{repro(monitor)}\n```"
                ),
                short_text="Policy monitoring pipeline status: 🍏",
            )
        else:
            self.liveness_channel.alert(
                level="🔥💀🔥💀🔥💀🔥",
                text=(
                    f"Monpoly did not report expected violation in policy"
                    f" '{formula}'. This indicates that the policy monitoring"
                    f" pipeline is broken.\n"
                    f"Repro:\n"
                    f"```\n{repro(monitor)}\n"
                    f"```\nTest logs: <{gurl(group)}>\n"
                ),
                short_text="💀 Policy monitoring pipeline broken 💀",
            )

    def _get_monpoly_builders(
        self,
        group: Group,
        pproc: PreProcessor,
    ) -> List[Monpoly]:
        eprint(f"Forming Monpoly builders for {group} with pre-processor {pproc.name}...")

        assert group.name in self.stat and "monpoly" in self.stat[group.name]
        self.stat[group.name]["monpoly"] = dict()

        monitors = []

        for formula in self.policies_to_monitor:
            # Obtain variable name mapping
            if formula not in self.var_seq:
                self.var_seq[formula] = Monpoly.get_variables(
                    docker=self.docker,
                    workdir=self.policies_path,
                    local_sig_file="predicates.sig",
                    local_formula=formula_local_path(formula),
                    hard_timeout=10.0,
                )

            self.stat[group.name]["monpoly"][formula] = dict()

            log_file = self.art_manager.event_stream_file(group, pproc.name)

            def repro(
                session: Monpoly,
                formula: str,
                log_file=log_file,
                group=group,
                repros: Dict[str, Dict[str, Set[Tuple[str, ...]]]] = self.repros,
                docker_starter=self.docker_starter,
            ) -> str:
                repro_cmd = session.cmd_wo_rss() + ("-log", f'"/repro/{log_file.name}"')

                # Save this repro in case we need to run it later
                if group.name not in repros:
                    repros[group.name] = dict()

                if formula not in repros[group.name]:
                    repros[group.name][formula] = set()
                else:
                    eprint(f"REPRO WARNING: multiple violations of policy {formula} by group name {group.name}")

                s = repros[group.name][formula]
                s.add(repro_cmd)

                if docker_starter is not None:
                    no_docker_cmd = session.cmd_wo_rss(enforce_no_docker=True) + ("-log", f'"/repro/{log_file.name}"')
                    res = " ".join(no_docker_cmd)
                    return "\n".join([docker_starter, res])
                else:
                    res = " ".join(repro_cmd)
                    return res

            def alert_h(
                arg: AlertHandlerParams,
                git_rev=self.git_revision,
                slack=self.slack,
                group=group,
                formula=formula,
                var_seq: Tuple[str, ...] = self.var_seq[formula],
            ) -> None:
                m = re.match(r"^@(\d+) \(time point (\d+)\): (.*)$", arg.message)
                if not m or len(m.groups()) != 3:
                    viol = arg.message
                else:
                    val_seq = ReproManager.parse_tuple(m.group(3))
                    if len(var_seq) != len(val_seq):
                        eprint(
                            f"could not match variable names against tuple values:\n"
                            f" var_seq = {', '.join(var_seq)};  \n"
                            f" val_seq = {', '.join(val_seq)};  \n"
                            f" original violation: {arg.message}"
                        )
                        viol = arg.message
                    else:
                        key_val_pairs = map(lambda pair: f'{pair[0]} = "{pair[1]}"', zip(var_seq, val_seq))
                        viol = f"@{m.group(1)} (time point {m.group(2)}):\n " + "\n ".join(key_val_pairs)
                slack.alert(
                    level="🎩",
                    text=f"`{arg.source}` reports that group `{group.name}`"
                    f" has violated policy {furl(git_rev, formula)}:\n"
                    f"```\n{viol}\n```\n"
                    f"Repro:\n"
                    f"```\n{repro(arg.session, formula)}\n"
                    f"```\nTest logs: <{gurl(group)}>\n",
                    short_text=f"Violation in {formula}",
                )

            def error_h(arg: ErrorHandlerParams, slack=self.slack, formula=formula, group=group) -> None:
                slack.alert(
                    level="🍊",
                    text=f"`{arg.source}` reports an error while checking"
                    f" policy `{formula}` against group `{group.name}`:\n"
                    f"```\n{arg.message}\n```\n"
                    f"Repro:\n"
                    f"```\n{repro(arg.session, formula)}\n"
                    f"```\nTest logs: <{gurl(group)}>\n",
                    short_text=f"Error from {arg.source}",
                )

            def exit_h(arg: ExitHandlerParams, slack=self.slack, formula=formula, group=group) -> None:
                if arg.exit_code != "0":
                    slack.alert(
                        level="🚱",
                        text=f"Monpoly exited with non-zero code `{arg.exit_code}`"
                        f" while checking policy `{formula}` of `{group.name}`\n"
                        f"Repro:\n"
                        f"```\n{repro(arg.session, formula)}\n"
                        f"```\nTest logs: <{gurl(group)}>\n",
                        short_text=f"Monpoly exited with code {arg.exit_code}",
                    )

            monitor = Monpoly(
                name=f"{log_file.stem}.{formula}",
                docker=self.docker,
                workdir=self.policies_path,
                stat=self.stat[group.name]["monpoly"][formula],
                reprodir=str(self.art_manager.artifacts_prefix()),
                local_sig_file="predicates.sig",
                local_formula=formula_local_path(formula),
                hard_timeout=60.0,
                alert_handler=alert_h,
                error_handler=error_h,
                exit_handler=exit_h,
                stop_at_first_viol=self.stop_at_first_violation,
            )
            monitors.append(monitor)

        return monitors

    def _monpoly_exception_handler(self, e: MonpolyException) -> None:
        if isinstance(e, MonpolyIoClosed):
            # Monpoly closes STDIN after the first violation if
            # the -stop_at_first_viol flag is set
            pass
        else:
            if self.fail:
                raise e
            self.slack.alert(
                level="🏮",
                text=f"Monpoly raised exception while running command `{e.cmd}`:\n```\n{str(e)}\n```",
                short_text=f"Exception from Monpoly: {e.msg}",
            )

    def _run_single_group(self, group: Group) -> None:
        # Check preconditions
        assert (
            not UniversalPreProcessor.is_global_infra_required(self.formulas_for_preproc)
            or group.global_infra is not None
        ), f"Global Infra is required but not available for {str(group)}"

        eprint(f"Starting monitoring for {group} ...")

        # Init statistics object for this group name
        self.stat[group.name] = {
            "pre_processor": dict(),
            "monpoly": dict(),
            "global_infra": None if group.global_infra is None else group.global_infra.to_dict(),
            "monpoly_global_timeout": False,
            "processed_raw_log_entries": 0,
        }

        # Create a PreProcessor instance
        pproc = UniversalPreProcessor(
            infra=group.global_infra,
            raw_logs_file=(self.art_manager.raw_logs_file(group) if Mode.raw in self.modes else None),
            formulas=(None if Mode.pre_processor_test in self.modes else self.formulas_for_preproc),
        )

        # Process the event stream
        try:
            with MultiMonitor(
                single_formula_monitors=(
                    self._get_monpoly_builders(group, pproc) if Mode.universal_policy in self.modes else []
                ),
                exception_handlers=(lambda e: self._monpoly_exception_handler(e)),
                event_stream_file=(
                    self.art_manager.event_stream_file(group, pproc.name)
                    if Mode.save_event_stream in self.modes
                    else None
                ),
                hard_timeout=self.hard_timeout,
            ) as monitor:
                for datum in pproc.run(group.logs):
                    monitor.submit(datum)
        except MonpolyGlobalTimeout as e:
            self.stat[group.name]["monpoly_global_timeout"] = True
            if self.fail:
                raise e
            self.slack.alert(
                level="🧨",
                text=f"Monpoly process `{e.cmd}` timed out:\n```\n{str(e)}\n```",
                short_text=f"MonpolyGlobalTimeout: {e.msg}",
            )
        finally:
            self.stat[group.name]["processed_raw_log_entries"] = pproc.get_progress()
            if pproc.raw_logs_file:
                pproc.flush(is_final=True)

        # Save test runtime statistics
        self.stat[group.name]["pre_processor"] = pproc.stat

        eprint(f"Monitoring completed for {group}.")

    def _run_liveness_check(self, group: Group):
        eprint("Starting liveness check ...")
        # Pre-process events that don't require global infra
        pproc = UniversalPreProcessor(infra=None, formulas=set(UniversalPreProcessor.get_formulas_wo_global_infra()))
        # Although the input stream is empty, at least one final event should still be generated
        event_stream = pproc.run(logs=[])
        # Run a dummy policy that is expected to fail for any non-empty log
        self.check_pipeline_alive(group, pproc, event_stream)
        eprint("Liveness check completed.")

    def run(self, groups: Dict[str, Group]):
        assert (
            len(groups) > 0
        ), "check if system tests are running via https://grafana.dfinity.systems/d/uwEFG_yGk/testing-dashboard"

        eprint("Starting policy monitoring ...")

        # Ensure that groups are processed in a deterministic order
        det_groups = list(map(lambda x: x[1], sorted(groups.items(), key=lambda x: x[0])))

        # Indicate that the pipeline is healthy end-to-end.
        # TODO: leveness typically means something else (safety vs. liveness);
        # TODO: use a different term, like e2e_checking
        if Mode.check_pipeline_liveness in self.modes:
            self._run_liveness_check(det_groups[0])  # pick single arbitrary group

        # Main loop
        for group in det_groups:
            self._run_single_group(group)

        eprint("Policy monitoring completed.")

    def reproduce_all_violations(self):
        rm = ReproManager(self.repros, self.stat, self.hard_timeout)
        rm.reproduce_all_violations()

    def save_statistics(self):
        self.art_manager.save_stat(self.stat)
