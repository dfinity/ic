from pathlib import Path
from typing import Dict

from util.print import eprint

from ..es_doc import EsDoc
from .group import Group


def read_logs(log_file: str) -> Dict[str, Group]:
    """Read and load logs from file"""
    eprint(f"Loading logs from {log_file} ...")
    with open(log_file, "r") as input_file:
        all_doc_reprs = eval(input_file.read())
        logs = [EsDoc(repr) for repr in all_doc_reprs]
    eprint(" done.")
    gid = Path(log_file).stem + "--pseudo"
    return {gid: Group(gid, logs, url="Omitted interaction with GitLab CI")}
