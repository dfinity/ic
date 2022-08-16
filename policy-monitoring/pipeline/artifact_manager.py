import pprint
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional

from util.print import eprint
from util.yaml import yaml

from .backend.group import Group


class ArtifactManager:
    def __init__(self, project_root: Path, artifacts_location: Path, sig: str):
        # A pseudo-unique string identifying this session
        self.sig = sig

        if artifacts_location.is_absolute():
            # Use case A: artifacts should be stored under an aboslute path
            # If run via Docker, use the following pattern:
            #  docker -v /absolute/path/on/host/artifacts:/artifacts
            #         monpoly_pipeline:latest
            #                --artifacts /artifacts
            self.artifacts_location = artifacts_location
        else:
            # Use case B: artifacts should be stored locally
            self.artifacts_location = project_root.joinpath(artifacts_location)

        self.ensure_file_structure()

    def artifacts_prefix(self) -> Path:
        return self.artifacts_location.joinpath(self.sig)

    def event_stream_file(self, group: Group, pre_proc_name: str) -> Path:
        return self.artifacts_prefix().joinpath(f"{group.safe_name()}.{pre_proc_name}.log")

    def raw_logs_file(self, group: Group) -> Path:
        return self.artifacts_prefix().joinpath(f"{group.safe_name()}.raw.log")

    def stat_file(self, type: str) -> Path:
        return self.artifacts_prefix().joinpath(f"stat.{type}")

    def global_infra_file(self, type: str, group_name: Optional[str]) -> Path:
        if group_name is None:
            fname = f"global_infra.{type}"
        else:
            fname = f"{group_name}.global_infra.{type}"
        return self.artifacts_prefix().joinpath(fname)

    def ensure_file_structure(self):
        return Path.mkdir(self.artifacts_prefix(), parents=True, exist_ok=False)

    def save_event_stream(self, group: Group, pre_proc_name: str, event_stream: Iterable[str]) -> None:
        output_file = str(self.event_stream_file(group, pre_proc_name).absolute())

        eprint(f"Saving event stream into '{output_file}' ...")

        with open(output_file, "w") as fout:
            fout.writelines(event_stream)

        eprint(f"Event stream saved; results written into '{output_file}'.")

    def save_raw_logs(self, group: Group):
        output_file = str(self.raw_logs_file(group).absolute())
        eprint(f"Pretty-printing raw logs into '{output_file}' ...")

        with open(output_file, "w") as fout:
            fout.write("[")  # the entire output should respresent a syntactically correct python object, e.g., a list
            pp = pprint.PrettyPrinter(indent=2, stream=fout)
            for log in group.logs:
                raw = pp.pformat(log).strip()  # avoid the \n after the comma
                fout.write(f"{raw},\n")
            fout.write("]")

        eprint(f"Pretty-printing raw logs completed; results written into '{output_file}'.")

    @staticmethod
    def _save_python(obj: Dict[str, Any], output_file: Path) -> None:
        with open(output_file, "w") as fout:
            pp = pprint.PrettyPrinter(indent=2, stream=fout)
            pp.pprint(obj)

    @staticmethod
    def save_yaml(obj: Dict[str, Any], output_file: Path) -> None:
        with open(output_file, "w") as fout:
            yaml.dump(obj, stream=fout)

    def _save(
        self, obj: Dict[str, Any], out_file_builder: Callable[[str], Path], python_format=False, yaml_format=False
    ) -> None:

        assert python_format or yaml_format, "need to specify at least one output format"
        output_files = []

        if python_format:
            python_file = out_file_builder("py")
            ArtifactManager._save_python(obj, python_file)
            output_files.append(python_file)
        if yaml_format:
            yaml_file = out_file_builder("yaml")
            ArtifactManager.save_yaml(obj, yaml_file)
            output_files.append(yaml_file)

        eprint(f"Statistics written into {', '.join(map(lambda p: str(p), output_files))}\n")

    def save_global_infra(self, group: Group) -> None:
        assert group.global_infra is not None
        self._save(
            group.global_infra.to_dict(),
            out_file_builder=lambda t: self.global_infra_file(t, group.safe_name()),
            yaml_format=True,
        )

    def save_stat(self, stat: Dict[str, Any], python_format=True, yaml_format=True) -> None:
        self._save(stat, out_file_builder=self.stat_file, python_format=python_format, yaml_format=yaml_format)
