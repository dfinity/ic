#!/usr/bin/env python3
#
# Utilities common to container functionality
#

import os
from pathlib import Path

import invoke


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
