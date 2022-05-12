import pprint
import re
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Iterator
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
from .ci import Group
from .es import Es
from .es import EsException
from .es_doc import EsDoc
from .es_doc import ReplicaDoc
from .global_infra import GlobalInfra
from .mode import is_raw_stream_reusable
from .mode import Mode
from .mode import multiple_preprocessing_needed
from .pre_processor import PreProcessor
from .pre_processor import UniversalPreProcessor


class PipelineException(Exception):
    pass


class Pipeline:

    REPO_BASE = "https://gitlab.com/ic-monitoring/es-log-processor/-/tree/main"

    @staticmethod
    def _formula_url(formula: str) -> str:
        return f"<{Pipeline.REPO_BASE}/mfotl-policies/{formula}/formula.mfotl" f"|{formula}>"

    def __init__(
        self,
        modes: Set[Mode],
        alert_service: AlertService,
        liveness_channel: AlertService,
        docker: bool,
        docker_starter: Optional[str] = None,  # only used in alerts with repros
        limit=0,
        global_infra: Optional[GlobalInfra] = None,
        artifacts_location="artifacts",
        formulas: Optional[Set[str]] = None,
    ):

        # The full path of the project root
        self._dir = Path(__file__).absolute().parent.parent

        # Corresponds to the name of
        # the [https://gitlab.com/ic-monitoring/mfotl-policies] repo
        self.policies_path = self._dir.joinpath("mfotl-policies")
        self.slack = alert_service
        self.liveness_channel = liveness_channel
        self.docker = docker
        self.docker_starter = docker_starter
        # A pseudo-unique string identifying this session
        self.sig = alert_service.signature
        self.modes = modes
        self.limit = limit

        self._es: Optional[Es] = None
        self._raw_logs_saved = False
        self._event_stream_saved = False
        self._global_infra = global_infra

        self.stat: Dict[str, Dict] = dict()

        # maps group ID to formula to set of repro cmds
        self.repros: Dict[str, Dict[str, Set[Tuple[str, ...]]]] = dict()

        # maps formula to tuple of variable names
        self.var_seq: Dict[str, Tuple[str, ...]] = dict()

        self.liveness_checked = False

        art_path = Path(artifacts_location)
        if art_path.is_absolute():
            # Use case A: artifacts should be stored under an aboslute path
            # If run via Docker, use the following pattern:
            #  docker -v /absolute/path/on/host/artifacts:/artifacts
            #         monpoly_pipeline:latest
            #                --artifacts /artifacts
            self.artifacts_location = art_path
        else:
            # Use case B: artifacts should be stored locally
            self.artifacts_location = self._dir.joinpath(art_path)

        self.formulas = formulas

    def artifacts_prefix(self) -> Path:
        return self.artifacts_location.joinpath(self.sig)

    def event_log_file(self, group: Group, pproc: PreProcessor) -> Path:
        return self.artifacts_prefix().joinpath(f"{group.gid}.{pproc.name}.log")

    def raw_es_logs_file(self, group: Group) -> Path:
        return self.artifacts_prefix().joinpath(f"{group.gid}.raw.log")

    def stat_file(self, type: str) -> Path:
        return self.artifacts_prefix().joinpath(f"stat.{type}")

    def global_infra_file(self, type: str, group_id: Optional[str]) -> Path:
        if group_id is None:
            fname = f"global_infra.{type}"
        else:
            fname = f"{group_id}.global_infra.{type}"
        return self.artifacts_prefix().joinpath(fname)

    def get_es_logs_for_group(self, group_id: str) -> Iterator[EsDoc]:
        if self._es is None:
            self._es = Es(es_url="elasticsearch.testnet.dfinity.systems")

        indices = self._es.find_indices(tag=group_id)
        if not indices:
            raise PipelineException(
                f"Could not find any ES indices with documents tagged `{group_id}`. "
                f"Try repeating this script in a few minutes if the hourly tests "
                f"have started recently)"
            )

        if self.limit > 0:
            page_size = min(10_000, self.limit)
        else:
            page_size = 10_000

        eprint("\nStarting to collect logs from ES ...")
        eprint(". = {page_size} events", flush=True)

        for i, doc in enumerate(self._es.stream(indices, tag=group_id, page_size=page_size)):
            yield EsDoc(doc)
            if self.limit > 0 and i == self.limit:
                eprint("\n", flush=True)
                break

        eprint(f"\nObtained {i + 1} entries from ES")

    def stream_into_file(self, group: Group, pproc: PreProcessor, event_stream: Iterable[str]) -> None:
        output_file = str(self.event_log_file(group, pproc).absolute())

        eprint(f"Saving event stream into '{output_file}' ...")

        with open(output_file, "w") as fout:
            fout.writelines(event_stream)

        eprint(f"Event stream saved; results written into '{output_file}'.")

    def check_pipeline_alive(self, group: Group, pproc: PreProcessor, event_stream: Iterable[str]) -> None:

        formula = "dummy"

        log_file = self.event_log_file(group, pproc)
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
            workdir=str(self.policies_path),
            reprodir=str(self.artifacts_prefix()),
            local_sig_file="predicates.sig",
            local_formula=str(Path(formula).joinpath("formula.mfotl")),
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

        print("Checking MFOTL policies in `%s` ..." % str(self.policies_path))

        self.stat[group.gid]["monpoly"] = dict()

        for formula in pproc.get_formulas():

            # Obtain variable name mapping
            if formula not in self.var_seq:
                self.var_seq[formula] = Monpoly.get_variables(
                    docker=self.docker,
                    workdir=str(self.policies_path),
                    local_sig_file="predicates.sig",
                    local_formula=str(Path(formula).joinpath("formula.mfotl")),
                    hard_timeout=10.0,
                )

            self.stat[group.gid]["monpoly"][formula] = dict()

            log_file = self.event_log_file(group, pproc)
            session_name = f"{log_file.stem}.{formula}"

            def repro(session: Monpoly) -> str:
                repro_cmd = session.cmd_wo_rss() + ("-log", f'"/repro/{log_file.name}"')

                # Save this repro in case we need to run it later
                if group.gid not in self.repros:
                    self.repros[group.gid] = dict()

                if formula not in self.repros[group.gid]:
                    self.repros[group.gid][formula] = set()
                else:
                    print(f"REPRO WARNING: multiple violations of " f"policy {formula} by group ID {group.gid}")

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
                    val_seq = self._parse_tuple(m.group(3))
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
                    short_text="Error from %s" % arg.source,
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
                        short_text="Monpoly exited with code %s" % arg.exit_code,
                    )

            with Monpoly(
                name=session_name,
                docker=self.docker,
                workdir=str(self.policies_path),
                stat=self.stat[group.gid]["monpoly"][formula],
                reprodir=str(self.artifacts_prefix()),
                local_sig_file="predicates.sig",
                local_formula=str(Path(formula).joinpath("formula.mfotl")),
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
                        text=f"Monpoly raised exception while running command" f" `{e.cmd}`:\n```\n{str(e)}\n```",
                        short_text="Exception from Monpoly: %s" % e.msg,
                    )

    def write_to_file(self, group: Group):
        output_file = str(self.raw_es_logs_file(group).absolute())
        eprint(f"Pretty-printing log stream into '{output_file}' ...")

        with open(output_file, "w") as fout:
            pp = pprint.PrettyPrinter(indent=2, stream=fout)
            pp.pprint(group.logs)

        eprint(f"Pretty-printing completed; results written into '{output_file}'.")

    def read_logs(self, log_file: str):
        """Read and load logs from file"""
        eprint(f"Loading logs from {log_file} ...")
        with open(log_file, "r") as input_file:
            all_doc_reprs = eval(input_file.read())
            logs = [EsDoc(repr) for repr in all_doc_reprs]
        eprint(" done.")
        gid = Path(log_file).stem + "--pseudo"
        return {gid: Group(gid, logs=logs, url="Omitted interaction with GitLab CI")}

    def download_logs(self, groups):
        for gid in groups:
            try:
                groups[gid].logs = self.get_es_logs_for_group(gid)
            except EsException as e:
                self.slack.alert(
                    level="🧀",
                    text="Elasticsearch exception:\n```\n%s\n```" % str(e),
                    short_text="Exception from Elasticsearch",
                )
                continue
            except PipelineException as e:
                self.slack.alert(
                    level="⌛",
                    text="Hourly pipeline exception:\n```\n%s\n```" % str(e),
                    short_text="Hourly pipeline exception",
                )
                continue

    def ensure_file_structure(self):
        return Path.mkdir(self.artifacts_prefix(), parents=True, exist_ok=False)

    def infer_global_infra(self, group: Group) -> GlobalInfra:
        eprint("Inferring global infra ...")
        orch_docs = [ReplicaDoc(doc.repr) for doc in group.logs if doc.is_replica()]
        infra = GlobalInfra(replica_docs=orch_docs)
        self.stat[group.gid]["global_infra"] = {
            "subnets": infra.get_subnet_info(),
            "original_subnet_membership": infra.get_original_subnet_membership(),
            "data_centers": infra.get_dc_info(),
            "host_addr_to_node_id_mapping": infra.get_host_addr_to_node_id_mapping(),
        }
        eprint("Inferring global infra done.")
        return infra

    def run(self, groups: Dict[str, Group]):
        print("Starting policy monitoring ...")

        for group in groups.values():
            # Init statistics object for this group ID
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
                self.write_to_file(group)

            if self.modes == set([Mode.raw]):
                # nothing else to do for this group id
                continue

            infra: Optional[GlobalInfra]
            if self._global_infra:
                eprint("Using provided global infra")
                infra = self._global_infra
                self.stat[group.gid]["global_infra"] = infra
                self._save_global_infra(group_id=None)
            elif UniversalPreProcessor.is_global_infra_required(self.formulas):
                infra = self.infer_global_infra(group)
                self._save_global_infra(group_id=group.gid)
            else:
                eprint("No global infra required")
                infra = None

            pproc = UniversalPreProcessor(infra, self.formulas)

            event_stream = pproc.run(group.logs)

            if multiple_preprocessing_needed(self.modes):
                event_stream = list(event_stream)

            if Mode.save_logs in self.modes:
                self.stream_into_file(group, pproc, event_stream)

            if Mode.universal_policy in self.modes:
                self.stream_into_monpoly(
                    group,
                    pproc,
                    event_stream,
                )

            # -- Save statistics --
            # 1. Run-time of the tests
            self.stat[group.gid]["pre_processor"] = pproc.stat

        if Mode.check_pipeline_liveness in self.modes and not self.liveness_checked:

            self.check_pipeline_alive(
                group,
                pproc,
                event_stream,
            )
            self.liveness_checked = True

        print("Policy monitoring completed.")

    @staticmethod
    def _parse_tuple(text: str) -> Tuple[str, ...]:
        """Parse Monpoly violation tuple. Take double quotes into account."""
        quoted = False
        text = text.strip("(").strip(")")
        if text == "":
            return ()
        res = []
        word = ""
        for char in text:
            if char == '"':
                quoted = not quoted
            elif not quoted and char == ",":
                res.append(word)
                word = ""
            else:
                word += char

        res.append(word)
        return tuple(res)

    @staticmethod
    def _count_violations(text: str) -> int:
        res = 0
        quoted = False
        opened = 0
        text = re.sub(r"\(time point \d+\)", "", text)
        for i, char in enumerate(text):
            if char == '"':
                quoted = not quoted
            elif not quoted and char == "(":
                res += 1
                opened += 1
            elif not quoted and char == ")":
                opened -= 1
                assert opened >= 0, f"invalid closing parenthesis at position {i}"

        assert opened == 0, f"{opened} too many opening parentheses"
        return res

    def run_all_repros(self) -> None:
        """
        Run instances of policy violations once again in non-interactive mode.

        This enables counting the precise number of violations in each case.

        In the future, this could also help making user feedback more precise.
        """
        eprint("Running all repros ...")

        import subprocess

        # pp = pprint.PrettyPrinter(indent=2)
        for group_id in self.repros:
            if group_id not in self.stat:
                self.stat[group_id] = dict()
            self.stat[group_id]["violations"] = dict()
            for formula in self.repros[group_id]:
                self.stat[group_id]["violations"][formula] = list()
                # repros: Set[ Tuple[str] ]
                repros = self.repros[group_id][formula]
                for repro_cmd in repros:
                    eprint(f" processing violation of policy {formula} @ group {group_id} ...", end="")

                    # Unquote all arguments since Popen adds its own quotes
                    repro_cmd_unquoted = tuple([arg.strip('"') for arg in repro_cmd])
                    # pp.pprint(repro_cmd_unquoted)
                    stdout, stderr = subprocess.Popen(
                        repro_cmd_unquoted, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    ).communicate()
                    self.stat[group_id]["violations"][formula].append(
                        {
                            "violations_count": self._count_violations(Monpoly.decode(stdout)),
                            "stderr_line_count": len(Monpoly.decode(stderr).split("\n")) - 1,
                            "repro_cmd": " ".join(repro_cmd),
                        }
                    )

                    eprint(" done.")

        eprint("All repros have terminated.")

    @staticmethod
    def _save_python(obj: Dict[str, Any], output_file: Path) -> None:
        with open(output_file, "w") as fout:
            pp = pprint.PrettyPrinter(indent=2, stream=fout)
            pp.pprint(obj)

    @staticmethod
    def _save_yaml(obj: Dict[str, Any], output_file: Path) -> None:
        from datetime import timedelta
        from ipaddress import IPv6Network, IPv6Address
        import yaml

        yaml.add_representer(IPv6Network, lambda dumper, data: dumper.represent_scalar("!IPv6Network", str(data)))
        yaml.add_representer(IPv6Address, lambda dumper, data: dumper.represent_scalar("!IPv6Address", str(data)))
        yaml.add_representer(set, lambda dumper, data: dumper.represent_sequence("!set", list(data)))
        yaml.add_representer(
            timedelta,
            lambda dumper, data: dumper.represent_scalar("!timedelta", "%ds %dus" % (data.seconds, data.microseconds)),
        )
        with open(output_file, "w") as fout:
            yaml.dump(obj, stream=fout)

    def _save(
        self, obj: Dict[str, Any], out_file_builder: Callable[[str], Path], python_format=False, yaml_format=False
    ) -> None:

        assert python_format or yaml_format, "need to specify at least one output format"
        output_files = []

        if python_format:
            python_file = out_file_builder("py")
            Pipeline._save_python(obj, python_file)
            output_files.append(python_file)
        if yaml_format:
            yaml_file = out_file_builder("yaml")
            Pipeline._save_yaml(obj, yaml_file)
            output_files.append(yaml_file)

        eprint(f"Statistics written into {', '.join(map(lambda p: str(p), output_files))}\n")

    def _save_global_infra(self, group_id: Optional[str]) -> None:
        assert group_id in self.stat, f"{group_id} not set in Pipeline.stat"
        assert "global_infra" in self.stat[group_id], f"'global_infra' not set in Pipeline.stat[{group_id}]"
        self._save(
            self.stat[group_id]["global_infra"],
            out_file_builder=lambda t: self.global_infra_file(t, group_id),
            yaml_format=True,
        )

    def save_stat(self, python_format=True, yaml_format=True) -> None:
        self._save(self.stat, out_file_builder=self.stat_file, python_format=python_format, yaml_format=yaml_format)
