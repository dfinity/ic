#!/usr/bin/env python3
#
# Assembling the build context of the IC-OS container builds, shared by the
# podman (build_container_filesystem_tar.py) and microVM
# (build_container_filesystem_vm.py) builders so that both see the same files.
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List


def arrange_context(context_dir: str, context_files: List[str], component_files: List[str]):
    """Copy the context files into context_dir, and the component files to their defined paths in it."""
    for context_file in context_files:
        shutil.copy(context_file, context_dir)
    arrange_component_files(context_dir, component_files)


def arrange_component_files(context_dir, component_files):
    """Add component files into the context directory by copying them to their defined paths."""
    for component_file in component_files:
        source_file, install_target = component_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        install_target = os.path.join(context_dir, install_target)
        make_directories(context_dir, os.path.dirname(install_target))
        shutil.copy(source_file, install_target)


def make_directories(context_dir, path):
    """
    Create path and its missing parents below context_dir with mode 0755.

    `COPY dir /dest` copies the directories' modes, so they must not depend on
    the umask of the build action.
    """
    missing = []
    while not os.path.isdir(path) and os.path.abspath(path) != os.path.abspath(context_dir):
        missing.append(path)
        path = os.path.dirname(path)
    for directory in reversed(missing):
        os.mkdir(directory)
        os.chmod(directory, 0o755)


def resolve_file_args(context_dir: str, file_build_args: List[str]) -> List[str]:
    """Resolve NAME=path build args to NAME=<first line of the file at path in the context>."""
    result = list()
    for arg in file_build_args:
        chunks = arg.split("=")
        if len(chunks) != 2:
            raise RuntimeError(f"File build arg '{arg}' is not valid")
        (name, pathname) = chunks

        path = Path(context_dir) / pathname

        with open(path, "r") as f:
            value = f.readline().strip()
            result.append(f"{name}={value}")

    return result
