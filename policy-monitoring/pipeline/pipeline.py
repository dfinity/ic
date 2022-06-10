import re
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Set
from typing import Tuple

from monpoly.monpoly import AlertHandlerParams
from monpoly.monpoly import ErrorHandlerParams
from monpoly.monpoly import ExitHandlerParams
from monpoly.monpoly import Monpoly
from monpoly.monpoly import MonpolyException
from monpoly.monpoly import MonpolyIoClosed
from util.print import eprint

from .alert import AlertService
from .artifact_manager import ArtifactManager
from .backend.group import Group
from .es_doc import ReplicaDoc
from .formula_manager import formula_local_path
from .global_infra import GlobalInfra
from .mode import is_raw_stream_reusable
from .mode import Mode
from .mode import multiple_preprocessing_needed
from .pre_processor import PreProcessor
from .pre_processor import UniversalPreProcessor
from .repro_manager import ReproManager


class Pipeline:

    REPO_BASE = "https://gitlab.com/ic-monitoring/es-log-processor/-/tree/main"

    @staticmethod
    def _formula_url(formula: str) -> str:
        return f"<{Pipeline.REPO_BASE}/mfotl-policies/{formula}/formula.mfotl|{formula}>"

    def __init__(
        self,
        policies_path: str,
        art_manager: ArtifactManager,
        modes: Set[Mode],
        alert_service: AlertService,
        liveness_channel: AlertService,
        docker: bool,
        docker_starter: Optional[str] = None,  # only used in alerts with repros
        global_infra: Optional[GlobalInfra] = None,
        formulas: Optional[Set[str]] = None,
    ):
        # Corresponds to the name of
        # the [https://gitlab.com/ic-monitoring/mfotl-policies] repo
        self.policies_path = policies_path

        # Ensure file structure
        self.art_manager = art_manager

        self.slack = alert_service
        self.liveness_channel = liveness_channel
        self.docker = docker
        self.docker_starter = docker_starter
        self.modes = modes

        self._global_infra = global_infra

        self.stat: Dict[str, Dict] = dict()

        # maps group names to formula to set of repro cmds
        self.repros: Dict[str, Dict[str, Set[Tuple[str, ...]]]] = dict()

        # maps formula to tuple of variable names
        self.var_seq: Dict[str, Tuple[str, ...]] = dict()

        self.liveness_checked = False

        self.formulas = formulas

    def check_pipeline_alive(self, group: Group, pproc: PreProcessor, event_stream: Iterable[str]) -> None:

        formula = "dummy"

        log_file = self.art_manager.event_stream_file(group, pproc.name)
        session_name = f"{log_file.stem}.{formula}"

        found_expected_violation = False

        def stdout_handler(arg: AlertHandlerParams) -> None:
            nonlocal found_expected_violation
            found_expected_violation = True

        def repro(session: Monpoly) -> str:
            if self.docker_starter is not None:
                repro_cmd = session.cmd_wo_rss(enforce_no_docker=True) + ("-log", f'"/repro/{log_file.name}"')
                res = " ".join(repro_cmd)
                return "\n".join([self.docker_starter, res])
            else:
                repro_cmd = session.cmd_wo_rss() + ("-log", f'"/repro/{log_file.name}"')
                res = " ".join(repro_cmd)
                return res

        with Monpoly(
            name=session_name,
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
                text="Policy monitoring pipeline status: operational (see reports in #ic-policy-alerts)",
                short_text="Policy monitoring pipeline status: 🍏",
            )
        else:
            self.liveness_channel.alert(
                level="🔥💀🔥💀🔥💀🔥",
                text=f"Monpoly did not report expected violation in policy"
                f" '{formula}'. This indicates that the policy monitoring"
                f" pipeline is broken.\n"
                f"Repro:\n"
                f"```\n{repro(monitor)}\n"
                f"```\nTest logs: <{group.url}>\n",
                short_text="💀 Policy monitoring pipeline broken 💀",
            )

    def stream_into_monpoly(
        self,
        group: Group,
        pproc: PreProcessor,
        event_stream: Iterable[str],
    ) -> None:

        assert group.gid in self.stat and "monpoly" in self.stat[group.gid]

        print(f"Checking MFOTL policy from `{self.policies_path}` ...")

        self.stat[group.gid]["monpoly"] = dict()

        for formula in pproc.get_formulas():

            # Obtain variable name mapping
            if formula not in self.var_seq:
                self.var_seq[formula] = Monpoly.get_variables(
                    docker=self.docker,
                    workdir=self.policies_path,
                    local_sig_file="predicates.sig",
                    local_formula=formula_local_path(formula),
                    hard_timeout=10.0,
                )

            self.stat[group.gid]["monpoly"][formula] = dict()

            log_file = self.art_manager.event_stream_file(group, pproc.name)
            session_name = f"{log_file.stem}.{formula}"

            def repro(session: Monpoly) -> str:
                repro_cmd = session.cmd_wo_rss() + ("-log", f'"/repro/{log_file.name}"')

                # Save this repro in case we need to run it later
                if group.gid not in self.repros:
                    self.repros[group.gid] = dict()

                if formula not in self.repros[group.gid]:
                    self.repros[group.gid][formula] = set()
                else:
                    print(f"REPRO WARNING: multiple violations of policy {formula} by group name {group.gid}")

                s: Set[Tuple[str, ...]]
                s = self.repros[group.gid][formula]
                s.add(repro_cmd)

                if self.docker_starter is not None:
                    no_docker_cmd = session.cmd_wo_rss(enforce_no_docker=True) + ("-log", f'"/repro/{log_file.name}"')
                    res = " ".join(no_docker_cmd)
                    return "\n".join([self.docker_starter, res])
                else:
                    res = " ".join(repro_cmd)
                    return res

            def alert_h(arg: AlertHandlerParams) -> None:
                m = re.match(r"^@(\d+) \(time point (\d+)\): (.*)$", arg.message)
                if not m or len(m.groups()) != 3:
                    viol = arg.message
                else:
                    var_seq = self.var_seq[formula]
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
                self.slack.alert(
                    level="🎩",
                    text=f"`{arg.source}` reports that group `{group.gid}`"
                    f" has violated policy {self._formula_url(formula)}:\n"
                    f"```\n{viol}\n```\n"
                    f"Repro:\n"
                    f"```\n{repro(arg.session)}\n"
                    f"```\nTest logs: <{group.url}>\n",
                    short_text=f"Violation in {formula}",
                )

            def error_h(arg: ErrorHandlerParams):
                self.slack.alert(
                    level="🍊",
                    text=f"`{arg.source}` reports an error while checking"
                    f" policy `{formula}` against group `{group.gid}`:\n"
                    f"```\n{arg.message}\n```\n"
                    f"Repro:\n"
                    f"```\n{repro(arg.session)}\n"
                    f"```\nTest logs: <{group.url}>\n",
                    short_text=f"Error from {arg.source}",
                )

            def exit_h(arg: ExitHandlerParams) -> None:
                if arg.exit_code != "0":
                    self.slack.alert(
                        level="🚱",
                        text=f"Monpoly exited with non-zero code `{arg.exit_code}`"
                        f" while checking policy `{formula}` of `{group.gid}`\n"
                        f"Repro:\n"
                        f"```\n{repro(arg.session)}\n"
                        f"```\nTest logs: <{group.url}>\n",
                        short_text=f"Monpoly exited with code {arg.exit_code}",
                    )

            with Monpoly(
                name=session_name,
                docker=self.docker,
                workdir=self.policies_path,
                stat=self.stat[group.gid]["monpoly"][formula],
                reprodir=str(self.art_manager.artifacts_prefix()),
                local_sig_file="predicates.sig",
                local_formula=formula_local_path(formula),
                hard_timeout=60.0,
                alert_handler=alert_h,
                error_handler=error_h,
                exit_handler=exit_h,
            ) as monitor:

                try:
                    for datum in event_stream:
                        monitor.submit(datum)
                except MonpolyIoClosed:
                    # Monpoly closes STDIN after the first violation if
                    # the -stop_at_first_viol flag is set
                    pass
                except MonpolyException as e:
                    self.slack.alert(
                        level="🏮",
                        text=f"Monpoly raised exception while running command `{e.cmd}`:\n```\n{str(e)}\n```",
                        short_text=f"Exception from Monpoly: {e.msg}",
                    )

    def infer_global_infra(self, group: Group) -> GlobalInfra:
        eprint("Inferring global infra ...")
        orch_docs = [ReplicaDoc(doc.repr) for doc in group.logs if doc.is_replica()]
        infra = GlobalInfra(replica_docs=orch_docs)
        self.stat[group.gid]["global_infra"] = infra.to_dict()
        eprint("Inferring global infra done.")
        return infra

    def _run_single_group(self, group: Group):
        # Init statistics object for this group name
        self.stat[group.gid] = {
            "pre_processor": dict(),
            "global_infra": dict(),
            "monpoly": dict(),
        }

        # We convert the iterator to List in order to enable two scans.
        # This could be avoided if there was another way of constructing
        # a GlobalInfra object.
        if True or is_raw_stream_reusable(self.modes):  # FIXME
            group.logs = list(group.logs)

        if Mode.raw in self.modes:
            self.art_manager.save_raw_logs(group)

        if self.modes == set([Mode.raw]):
            # nothing else to do for this group name
            return

        # Obtain Global Infra
        infra: Optional[GlobalInfra]
        if self._global_infra:
            eprint("Using provided global infra")
            infra = self._global_infra
            self.stat[group.gid]["global_infra"] = infra.to_dict()
            group.global_infra = infra
            self.art_manager.save_global_infra(group)
        elif UniversalPreProcessor.is_global_infra_required(self.formulas):
            infra = self.infer_global_infra(group)
            group.global_infra = infra
            self.art_manager.save_global_infra(group)
        else:
            eprint("No global infra required")
            infra = None

        pproc = UniversalPreProcessor(infra, self.formulas)
        event_stream = pproc.run(group.logs)

        if multiple_preprocessing_needed(self.modes):
            event_stream = list(event_stream)

        if Mode.save_event_stream in self.modes:
            self.art_manager.save_event_stream(group, pproc.name, event_stream)

        if Mode.universal_policy in self.modes:
            self.stream_into_monpoly(
                group,
                pproc,
                event_stream,
            )
        # Save test runtime statistics
        self.stat[group.gid]["pre_processor"] = pproc.stat

    def _run_liveness_check(self, group: Group):
        pproc = UniversalPreProcessor(infra=None, formulas=self.formulas)
        event_stream = pproc.run(group.logs)
        self.check_pipeline_alive(group, pproc, event_stream)

    def run(self, groups: Dict[str, Group]):
        print("Starting policy monitoring ...")

        # Ensure that groups are processed in a deterministic order
        det_groups = list(map(lambda x: x[1], sorted(groups.items(), key=lambda x: x[0])))

        for group in det_groups:
            self._run_single_group(group)

        if Mode.check_pipeline_liveness in self.modes and not self.liveness_checked:
            self._run_liveness_check(det_groups[0])  # pick single arbitrary group
            self.liveness_checked = True

        print("Policy monitoring completed.")

    def reproduce_all_violations(self):
        rm = ReproManager(self.repros, self.stat)
        rm.reproduce_all_violations()

    def save_statistics(self):
        self.art_manager.save_stat(self.stat)
