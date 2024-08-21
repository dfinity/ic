#!/usr/bin/env python3
#
# Build Dockerfile.base image and export as a tar file
#
from __future__ import annotations

import atexit
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List

import invoke
from loguru import logger as log
from simple_parsing import ArgumentParser, field


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


def build_image(image_tag: str, dockerfile: str, context_dir: str, build_args: List[str]):
    build_arg_strings = [f"--build-arg \"{v}\"" for v in build_args]
    build_arg_strings_joined = ' '.join(build_arg_strings)

    log.info("Building image...")
    cmd = f"podman build --squash-all --no-cache --tag {image_tag} {build_arg_strings_joined} --file {dockerfile} {context_dir}"
    invoke.run(cmd)
    log.info("Image built successfully")


def save_image(image_tag: str, output_file: str):
    log.info("Saving image to tar file")
    cmd = f"podman image save --output {output_file} {image_tag}"
    invoke.run(cmd)
    invoke.run("sync") # For determinism (?)

    output_path = Path(output_file)
    assert output_path.exists()
    log.info("Image saved successfully")


# TODO def upload_to_docker_io()


def main():
    parser = ArgumentParser()
    parser.add_arguments(Args, dest="fancy")
    parser.add_argument("--context-file", dest="context_files", type=Path, action="append", help="Files to drop directly into the build context.", required=True)
    args = parser.parse_args()

    log.info(f"Using args: {args}")

    build_args = list(args.fancy.build_args or [])
    context_dir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", context_dir], check=True))

    # Add all context files directly into dir
    for context_file in args.context_files:
        shutil.copy(context_file, context_dir)

    build_image(args.fancy.image_tag, args.fancy.dockerfile, context_dir, build_args)
    save_image(args.fancy.image_tag, args.fancy.output)
    invoke.run(f"podman image rm -f {args.fancy.image_tag}")


if __name__ == "__main__":
    main()
