#!/usr/bin/env python3
#
# Common utilities
#
import os
from pathlib import Path

import invoke
from loguru import logger as log


def path_owned_by_root(p: Path) -> bool:
    file_owner_uid = os.stat(p).st_uid
    root_uid = 0
    return file_owner_uid == root_uid


def take_ownership_of_file(file: Path):
    """Make `file` owned by current user"""
    current_user = invoke.run("whoami").stdout.strip()
    invoke.run(f"sudo chown {current_user} {file}")
    invoke.run(f"sudo chgrp {current_user} {file}")


def remove_image(container_cmd: str, image_tag: str):
    invoke.run(f"{container_cmd} image rm -f {image_tag}")


def purge_podman(container_cmd: str):
    log.info("Cleaning up podman...")
    cmd = f"{container_cmd} system prune --all --volumes --force"
    invoke.run(cmd)


def parse_size(s):
    if s[-1] == "k" or s[-1] == "K":
        return 1024 * int(s[:-1])
    elif s[-1] == "m" or s[-1] == "M":
        return 1024 * 1024 * int(s[:-1])
    elif s[-1] == "g" or s[-1] == "G":
        return 1024 * 1024 * 1024 * int(s[:-1])
    else:
        return int(s)
