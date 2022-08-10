from pathlib import Path
from typing import Dict
from typing import Iterator

from pipeline.es_doc import EsDoc
from util.print import eprint

from .group import Group


def read_logs(log_file: str) -> Dict[str, Group]:
    """Read and load logs from file"""
    eprint(f"Loading logs from {log_file} ...")
    with open(log_file, "r", encoding="utf-8") as input_file:
        all_doc_reprs = eval(input_file.read())
        logs = [EsDoc(repr) for repr in all_doc_reprs]
    eprint(" done.")
    gname = Path(log_file).stem + "--pseudo"
    return {gname: Group(gname, logs, url="Omitted interaction with GitLab CI")}


def safe_log_stream(file_path: str) -> Iterator[EsDoc]:
    with open(file_path, "r", encoding="utf-8") as fh:
        while True:
            line = fh.readline()
            if not line:
                return
            obj_str = line.strip().strip("[],")
            if not obj_str:
                continue
            repr = eval(obj_str)
            yield EsDoc(repr)


def stream_file(log_file: str) -> Dict[str, Group]:
    gid = Path(log_file).stem + "--pseudo"
    return {gid: Group(gid, logs=safe_log_stream(log_file), url="Omitted interaction with GitLab CI")}
