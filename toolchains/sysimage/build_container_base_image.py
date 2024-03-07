#!/usr/bin/env python3
#
# Build Dockerfile.base image and export as a tar file
#
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import invoke
from container_utils import (
    generate_container_command,
    path_owned_by_root,
    process_temp_sys_dir_args,
    remove_image,
    take_ownership_of_file,
)
from loguru import logger as log
from simple_parsing import field, flag, parse


@dataclass
class Args:
    """Build a given Dockerfile and save image file."""

    # Context directory. Where building the Dockerfile will occur and search for files.
    context_dir: Path

    # Dockerfile to build
    dockerfile: Path

    image_tag: str
    """Image tag. Output file will contain this. The same tag will appear in local container image storage when loaded.
    """

    # Output file. Will be saved as a tar archive
    output: str

    # "Container engine (podman) will use the specified dir to store its system files. It will remove the files before exiting.
    temp_container_sys_dir: Optional[str]

    # Create and mount a tmpfs to store its system files. It will be unmounted before exiting.
    tmpfs_container_sys_dir: bool = flag(default=False)

    build_args: List[str] = field(default_factory=list)
    """Container build time variables.
    Each argument should be in form VARIABLE=value.
    Specify multiple build args using the single flag.
    E.g., script.py --build_args "ARG=value" "ARG2=value"
    """

    def __post_init__(self):
        assert self.context_dir.exists()
        assert self.dockerfile.exists()


def build_image(container_cmd: str, image_tag: str, dockerfile: str, context_dir: str):
    log.info("Building image...")
    cmd = f"{container_cmd} build --squash-all --no-cache --tag {image_tag} --file {dockerfile} {context_dir}"
    invoke.run(cmd)
    log.info("Image built successfully")


def save_image(container_cmd: str, image_tag: str, output_file: str):
    log.info("Saving image to tar file")
    cmd = f"{container_cmd} image save --output {output_file} {image_tag}"
    invoke.run(cmd)
    invoke.run("sync") # For determinism (?)

    # Using sudo w/ podman requires changing permissions on the output tar file (not the tar contents)
    output_path = Path(output_file)
    assert path_owned_by_root(output_path), \
        f"'{output_path}' not owned by root. Remove this and the next line."
    take_ownership_of_file(output_path)

    assert output_path.exists()
    log.info("Image saved successfully")


# TODO def upload_to_docker_io()


def main():
    args: Args = parse(Args)
    log.info(f"Using args: {args}")
    temp_sys_dir = process_temp_sys_dir_args(args.temp_container_sys_dir, args.tmpfs_container_sys_dir)

    container_cmd = generate_container_command("sudo podman ", temp_sys_dir)

    build_image(container_cmd, args.image_tag, args.dockerfile, args.context_dir)
    save_image(container_cmd, args.image_tag, args.output)
    remove_image(container_cmd, args.image_tag) # No harm removing if in the tmp dir


if __name__ == "__main__":
    main()
