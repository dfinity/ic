#!/usr/bin/env python3
#
# Build Dockerfile.base image and export as a tar file
#
from __future__ import annotations

import atexit
import os
import shutil
import signal
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List

import invoke
from loguru import logger as log
from simple_parsing import ArgumentParser, field

from toolchains.sysimage.utils import (
    path_owned_by_root,
    purge_podman,
    remove_image,
    take_ownership_of_file,
)


@dataclass
class Args:
    """Build a given Dockerfile and save image file."""

    # Dockerfile to build
    dockerfile: Path

    image_tag: str
    """Image tag. Output file will contain this. The same tag will appear in local container image storage when loaded.
    """

    # Output file. Will be saved as a tar archive
    output: str

    build_args: List[str] = field(default_factory=list)
    """Container build time variables.
    Each argument should be in form VARIABLE=value.
    Specify multiple build args using the single flag.
    E.g., script.py --build_args "ARG=value" "ARG2=value"
    """

    def __post_init__(self):
        assert self.dockerfile.exists()


def build_image(container_cmd: str, image_tag: str, dockerfile: str, context_dir: str, build_args: List[str]):
    build_arg_strings = [f'--build-arg "{v}"' for v in build_args]
    build_arg_strings_joined = " ".join(build_arg_strings)

    log.info("Building image...")
    cmd = f"{container_cmd} build --squash-all --no-cache --tag {image_tag} {build_arg_strings_joined} --file {dockerfile} {context_dir}"
    invoke.run(cmd)
    log.info("Image built successfully")


def save_image(container_cmd: str, image_tag: str, output_file: str):
    log.info("Saving image to tar file")
    cmd = f"{container_cmd} image save --output {output_file} {image_tag}"
    invoke.run(cmd)
    invoke.run("sync")  # For determinism (?)

    # Using sudo w/ podman requires changing permissions on the output tar file (not the tar contents)
    output_path = Path(output_file)
    assert path_owned_by_root(output_path), f"'{output_path}' not owned by root. Remove this and the next line."
    take_ownership_of_file(output_path)

    assert output_path.exists()
    log.info("Image saved successfully")


def main():
    parser = ArgumentParser()
    parser.add_arguments(Args, dest="fancy")
    parser.add_argument(
        "--context-file",
        dest="context_files",
        type=Path,
        action="append",
        help="Files to drop directly into the build context.",
        required=True,
    )
    args = parser.parse_args()

    log.info(f"Using args: {args}")

    build_args = list(args.fancy.build_args or [])
    context_dir = tempfile.mkdtemp()

    # Add all context files directly into dir
    for context_file in args.context_files:
        shutil.copy(context_file, context_dir)

    if "TMPFS_TMPDIR" in os.environ:
        tmpdir = os.environ.get("TMPFS_TMPDIR")
    else:
        log.info("TMPFS_TMPDIR env variable not available, this may be slower than expected")
        tmpdir = os.environ.get("TMPDIR")

    root = tempfile.mkdtemp(dir=tmpdir)
    run_root = tempfile.mkdtemp(dir=tmpdir)
    container_cmd = f"sudo podman --root {root} --runroot {run_root}"

    atexit.register(lambda: purge_podman(container_cmd))
    signal.signal(signal.SIGTERM, lambda: purge_podman(container_cmd))
    signal.signal(signal.SIGINT, lambda: purge_podman(container_cmd))

    build_image(container_cmd, args.fancy.image_tag, args.fancy.dockerfile, context_dir, build_args)
    save_image(container_cmd, args.fancy.image_tag, args.fancy.output)
    remove_image(container_cmd, args.fancy.image_tag)  # No harm removing if in the tmp dir

    # tempfile cleanup is handled by proc_wrapper.sh


if __name__ == "__main__":
    main()
