#!/usr/bin/env python3
#
# Utilities common to container functionality
#

from __future__ import annotations

import atexit
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import invoke

SYS_DIR_PREFIX = "podman_sys_dir_"
DEFAULT_TMP_PREFIX = "/tmp"


def path_owned_by_root(p: Path) -> bool:
    file_owner_uid = os.stat(p).st_uid
    root_uid = 0
    return file_owner_uid == root_uid


def take_ownership_of_file(file: Path):
    """Make `file` owned by current user"""
    current_user = invoke.run("whoami").stdout.strip()
    invoke.run(f"sudo chown {current_user} {file}")
    invoke.run(f"sudo chgrp {current_user} {file}")



def make_tmpfs(base_dir: str = DEFAULT_TMP_PREFIX) -> str:
    """
    Mount a tmpfs volume in a subdirectory of the given `base_dir`.
    Auto unmount at exit.

    This seems to work across environments:
      - CI - running K8S containerd runners
      - ci/container/container-run.sh

    Returns the unique tmpfs mount point
    """
    unique_tag = os.getpid()
    temp_sys_dir = f"/tmp/tmpfs_{unique_tag}"
    tmpfs_name = f"tmpfs_{unique_tag}"
    invoke.run(f"mkdir -p {temp_sys_dir}")
    invoke.run(f"sudo mount -t tmpfs {tmpfs_name} {temp_sys_dir}")
    atexit.register(lambda: invoke.run(f"sudo umount {temp_sys_dir}"))
    return temp_sys_dir


def process_temp_sys_dir_args(temp_container_sys_dir: Optional[str],
                              tmpfs_container_sys_dir: Optional[str]) -> Optional[str]:
    """

    Handles two program arguments - user chooses either temp dir or tmpfs dir for podman activities.
    Returns a string pointing at the temporary base dir or None.
    """
    assert not (temp_container_sys_dir and tmpfs_container_sys_dir), \
        "temp_container_sys_dir and tmpfs_container_sys_dir flags are mutually exclusive"
    if temp_container_sys_dir:
        return temp_container_sys_dir

    if tmpfs_container_sys_dir:
        return make_tmpfs()

    return None


@dataclass(frozen=True)
class ContainerSystemDirs:
    """Data corresponds to podman args: --root, --runroot"""

    sys_dir: Path
    run_dir: Path


def create_container_system_dirs(base_dir: Path) -> ContainerSystemDirs:
    container_sys_dir = tempfile.mkdtemp(prefix=SYS_DIR_PREFIX, dir=base_dir)
    container_run_dir = tempfile.mkdtemp(prefix=SYS_DIR_PREFIX, dir=base_dir)

    # podman runs via sudo, so the files have root uid/gid.
    # Use sudo to remove the files.
    # Remove sudo when rootless podman is functional
    # Remove this whole function when podman heisenbug no longer applies - see NODE-973
    atexit.register(lambda: invoke.run(f"sudo rm -rf {container_sys_dir} {container_run_dir}"))

    return ContainerSystemDirs(Path(container_sys_dir),
                               Path(container_run_dir))


def remove_image(container_cmd: str, image_tag: str):
    invoke.run(f"{container_cmd} image rm -f {image_tag}")


def generate_container_command(default_command: str, temp_sys_dir: Optional[Path]) -> str:
    if temp_sys_dir:
        dirs = create_container_system_dirs(temp_sys_dir)
        return f"{default_command} --root {dirs.sys_dir} --runroot {dirs.run_dir} "

    return default_command

