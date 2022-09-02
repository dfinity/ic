from pathlib import Path
from typing import Iterable
from typing import Iterator
from typing import Optional

from pipeline.es_doc import EsDoc
from pipeline.global_infra import GlobalInfra
from util.print import eprint


class Group:
    def __init__(
        self,
        name: str,
        logs: Iterable[EsDoc] = [],
        global_infra: Optional[GlobalInfra] = None,
        generation: Optional[int] = None,  # an optional integer to use in the safe name's suffix
    ):
        self.logs = logs
        self.name = name
        self.global_infra = global_infra
        self._generation = generation

    def __str__(self) -> str:
        """Logging-friendly representation"""
        optional_fields = []
        url = self.job_url()
        if url:
            optional_fields.append(f"url={url}")
        return f"<Group name={self.name} {' '.join(optional_fields)}>"

    def infer_global_infra(self) -> None:
        eprint(f"Inferring global infra for {str(self)}... (Log stream will be fully loaded into memory)")
        self.logs = list(self.logs)
        self.global_infra = GlobalInfra.fromLogs(self.logs)
        eprint(f"Done inferring global infra for {str(self)}.")

    def pot_name(self) -> str:
        # Example group ID: "boundary_nodes_pre_master__boundary_nodes_pot-2784039865"
        # Corresponding pot name: "boundary_nodes_pot"
        return self.name.split("__")[-1].split("-")[0]

    @staticmethod
    def is_group_name_local(jid: str) -> bool:
        return sum([1 for c in jid if c == "-"]) > 1

    def job_id(self) -> Optional[int]:
        # Example group IDs:
        # "boundary_nodes_pre_master__boundary_nodes_pot-2784039865"
        #   ==> run in CI
        # "boundary_nodes_pre_master__boundary_nodes_pot-username-zh1-spm99_zh7_dfinity_network-2784039865"
        #   ==> run locally (no CI job exists; None will be returned)
        # Corresponding job ID: 2784039865
        # Note:
        # - A group name might not have a CI job ID associated with it if it has been created for mainnet logs
        #   In that case, this method will return None.
        if self.is_group_name_local(self.name):
            return None
        suffix = self.name.split("-")[-1]
        if suffix.isdigit():
            return int(suffix)
        return None

    def job_url(self) -> Optional[str]:
        id = self.job_id()
        if not id:
            return None
        else:
            return f"https://gitlab.com/dfinity-lab/public/ic/-/jobs/{id}"

    def safe_name(self) -> str:
        """Similar to self.name but avoids overriding existing files"""
        if self._generation is None:
            return self.name
        return f"{self.name}--{self._generation}"

    @staticmethod
    def _safe_log_stream(file: Path) -> Iterator[EsDoc]:
        with open(file, "r", encoding="utf-8") as fh:
            while True:
                line = fh.readline()
                if not line:
                    return
                obj_str = line.strip().strip("[],")
                if not obj_str:
                    continue
                repr = eval(obj_str)
                yield EsDoc(repr)

    @classmethod
    def _StreamFromFile(Self, log_file: Path) -> "Group":
        """Create group and set up a logs stream"""
        gname = Path(log_file).stem + "--pseudo"
        return Group(gname, logs=Self._safe_log_stream(log_file))

    @classmethod
    def _LoadFromFile(Self, log_file: Path) -> "Group":
        """Create group and load logs from file"""
        eprint(f"Loading logs from {log_file} ...")
        with open(log_file, "r") as input_file:
            all_doc_reprs = eval(input_file.read())
            logs = [EsDoc(repr) for repr in all_doc_reprs]
        eprint(f"Done loading logs from {log_file}.")
        # Example file name: "boundary_nodes_pre_master__boundary_nodes_pot-2784039865--0.raw.log"
        components = log_file.stem.split("--")
        return Group(name=components[0], logs=logs, generation=len(components) - 1)

    @classmethod
    def fromFile(Self, log_file: Path, as_stream=True) -> "Group":
        if as_stream:
            return Self._StreamFromFile(log_file)
        else:
            return Self._LoadFromFile(log_file)
