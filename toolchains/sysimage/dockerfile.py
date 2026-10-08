#!/usr/bin/env python3
#
# A deliberately small Dockerfile interpreter for the IC-OS container builds.
#
# It turns a Dockerfile plus build arguments into a flat list of steps (COPY and
# RUN) on top of a single base image, which build_container_filesystem_vm.py
# then executes in a microVM instead of `podman build`. Only the subset of the
# Dockerfile syntax used by the IC-OS Dockerfiles is supported, and anything
# else is rejected rather than silently interpreted differently:
#
# * `ARG name[=default]`, before the first FROM (usable in FROM lines) or in a
#   stage (visible to that stage's RUN steps as environment variables).
# * `FROM image|stage [AS name]`, where the stages leading to the last one form
#   a single chain (each derives from the previous one).
# * `USER root[:root]` (the steps always run as root).
# * `COPY [--chmod=MODE] src... dest`, with sources relative to the context.
# * `RUN command` (shell form, run with `/bin/sh -c`).
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
# Parser directives, e.g. `# escape=` or `# syntax=`, which change how the rest is parsed.
_DIRECTIVE = re.compile(r"#\s*[A-Za-z]+\s*=")


class DockerfileError(Exception):
    pass


@dataclass(frozen=True)
class Copy:
    sources: List[str]
    destination: str
    chmod: Optional[str] = None


@dataclass(frozen=True)
class Run:
    command: str
    # Build arguments declared in the stage, exported to the command.
    args: Dict[str, str] = field(default_factory=dict)


Step = Union[Copy, Run]


@dataclass
class Stage:
    base: str  # an image reference or the name of an earlier stage
    name: Optional[str]
    steps: List[Step] = field(default_factory=list)
    args: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Plan:
    base_image: str
    steps: List[Step]


def substitute(value: str, variables: Dict[str, str]) -> str:
    # Only $NAME and ${NAME}: no ${NAME:-default} or other modifiers, no \$ escapes.
    if "\\$" in value or "${" in _VARIABLE.sub("", value):
        raise DockerfileError(f"unsupported variable syntax in {value!r}")

    def replace(match):
        name = match.group(1) or match.group(2)
        return variables.get(name, "")

    return _VARIABLE.sub(replace, value)


def logical_lines(text: str) -> List[str]:
    """Join continuation lines and drop comments and blank lines."""
    lines = []
    current = ""
    for number, raw in enumerate(text.splitlines()):
        stripped = raw.strip()
        if not lines and not current and _DIRECTIVE.match(stripped):
            raise DockerfileError(f"unsupported parser directive on line {number + 1}: {stripped}")
        if stripped.startswith("#"):
            continue
        if current and not stripped:
            # Docker skips empty lines in a continuation.
            continue
        if raw.rstrip().endswith("\\"):
            # Like Docker, drop the backslash and the newline.
            current += raw.rstrip()[:-1]
            continue
        current += raw
        if current.strip():
            lines.append(current.strip())
        current = ""
    if current.strip():
        raise DockerfileError("Dockerfile ends with a line continuation")
    return lines


def parse(text: str, build_args: Dict[str, str]) -> List[Stage]:
    global_args: Dict[str, str] = {}
    stages: List[Stage] = []
    for line in logical_lines(text):
        instruction, _, rest = line.partition(" ")
        instruction = instruction.upper()
        rest = rest.strip()
        stage = stages[-1] if stages else None
        if instruction == "ARG":
            name, has_default, default = rest.partition("=")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise DockerfileError(f"unsupported ARG: {line}")
            if default[:1] in ("'", '"'):
                raise DockerfileError(f"unsupported quoted ARG default: {line}")
            if has_default:
                value = build_args.get(name, default)
            else:
                # Like Docker, a stage's ARG without a default inherits the global one.
                value = (
                    build_args.get(name, global_args.get(name, "")) if stage is not None else build_args.get(name, "")
                )
            if stage is None:
                global_args[name] = value
            else:
                stage.args[name] = value
        elif instruction == "FROM":
            words = rest.split()
            if len(words) == 1:
                base, name = words[0], None
            elif len(words) == 3 and words[1].upper() == "AS":
                base, name = words[0], words[2]
            else:
                raise DockerfileError(f"unsupported FROM: {line}")
            if base.startswith("--"):
                raise DockerfileError(f"unsupported FROM flag: {line}")
            stages.append(Stage(base=substitute(base, global_args), name=name))
        elif stage is None:
            raise DockerfileError(f"{instruction} before the first FROM")
        elif instruction == "USER":
            if rest not in ("root", "root:root", "0", "0:0"):
                raise DockerfileError(f"only USER root is supported: {line}")
        elif instruction == "RUN":
            if rest.startswith("[") or rest.startswith("--"):
                raise DockerfileError(f"only the shell form of RUN without flags is supported: {line}")
            stage.steps.append(Run(command=rest, args=dict(stage.args)))
        elif instruction == "COPY":
            words = rest.split()
            chmod = None
            while words and words[0].startswith("--"):
                flag = words.pop(0)
                if flag.startswith("--chmod="):
                    chmod = flag[len("--chmod=") :]
                    if not re.fullmatch(r"[0-7]{3,4}", chmod):
                        raise DockerfileError(f"only octal --chmod is supported: {line}")
                else:
                    raise DockerfileError(f"unsupported COPY flag: {line}")
            if len(words) < 2 or rest.startswith("["):
                raise DockerfileError(f"unsupported COPY: {line}")
            *sources, destination = [substitute(w, stage.args) for w in words]
            for source in sources:
                if any(c in source for c in "*?[") or source.startswith("/") or ".." in source.split("/"):
                    raise DockerfileError(f"unsupported COPY source {source!r}: {line}")
            stage.steps.append(Copy(sources=sources, destination=destination, chmod=chmod))
        else:
            raise DockerfileError(f"unsupported instruction {instruction}: {line}")
    if not stages:
        raise DockerfileError("no FROM in Dockerfile")
    return stages


def plan(text: str, build_args: Dict[str, str]) -> Plan:
    """Return the base image and the steps that build the last stage of the Dockerfile."""
    stages = parse(text, build_args)
    by_name = {stage.name: stage for stage in stages if stage.name}
    chain: List[Stage] = []
    stage = stages[-1]
    while True:
        chain.insert(0, stage)
        parent = by_name.get(stage.base)
        if parent is None:
            break
        if parent in chain:
            raise DockerfileError(f"stage cycle at {stage.base}")
        stage = parent
    steps: List[Step] = []
    for stage in chain:
        steps.extend(stage.steps)
    return Plan(base_image=chain[0].base, steps=steps)
