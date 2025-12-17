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
    build_arg_strings = [f'--build-arg "{v}"' for v in build_args]
    build_arg_strings_joined = " ".join(build_arg_strings)

    log.info("Building image...")
    cmd = f"podman build --squash-all --no-cache --tag {image_tag} {build_arg_strings_joined} --file {dockerfile} {context_dir}"
    invoke.run(cmd)
    log.info("Image built successfully")


def save_image(image_tag: str, output_file: str):
    log.info("Saving image to tar file")
    cmd = f"podman image save --output {output_file} {image_tag}"
    invoke.run(cmd)
    invoke.run("sync")  # For determinism (?)

    output_path = Path(output_file)
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
    build_args = args.fancy.build_args
    dockerfile = args.fancy.dockerfile
    image_tag = args.fancy.image_tag
    output = args.fancy.output

    log.info(f"Using args: {args}")

    # NOTE: /usr/bin/nsenter is required to be on $PATH for this version of
    # podman (no longer in latest version). bazel strips this out - add it back
    # manually, for now.
    os.environ["PATH"] = ":".join([x for x in [os.environ.get("PATH"), "/usr/bin"] if x is not None])

    def cleanup():
        invoke.run(f"podman rm -f {image_tag}")
        invoke.run(f"podman rm -f {image_tag}_container")

    atexit.register(lambda: cleanup())
    signal.signal(signal.SIGTERM, lambda: cleanup())
    signal.signal(signal.SIGINT, lambda: cleanup())

    build_args = list(build_args or [])
    context_dir = tempfile.mkdtemp()

    # Add all context files directly into dir
    for context_file in args.context_files:
        shutil.copy(context_file, context_dir)

    build_image(image_tag, dockerfile, context_dir, build_args)
    save_image(image_tag, output)


if __name__ == "__main__":
    main()
