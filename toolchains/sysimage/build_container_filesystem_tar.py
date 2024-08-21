#!/usr/bin/env python3
#
# Build a container image and extract the single flattened filesystem into a tar file.
from __future__ import annotations

import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, TypeVar

import invoke


@dataclass(frozen=True)
class BaseImageOverride:
    image_file: Path
    image_tag: str

    def __post_init__(self):
        assert self.image_tag is not None
        assert self.image_file is not None
        assert self.image_file.exists()


ReturnType = TypeVar('ReturnType') # https://docs.python.org/3/library/typing.html#generics
def retry(func: Callable[[], ReturnType], num_retries: int = 3 ) -> ReturnType:
    """
    Call the given `func`. If an exception is raised, print, and retry `num_retries` times.
    Back off retries by sleeping for at least 5 secs + an exponential increase.
    Exception is not caught on the last try.
    """
    BASE_BACKOFF_WAIT_SECS = 5
    for i in range(num_retries):
        try:
            return func()
        except Exception as e:
            print(f"Exception occurred: {e}", file=sys.stderr)
            print(f"Retries left: {num_retries - i}", file=sys.stderr)
            wait_time_secs = BASE_BACKOFF_WAIT_SECS + i**2
            print(f"Waiting for next retry (secs): {wait_time_secs}")
            time.sleep(wait_time_secs) # 5, 6, 9, 14, 21, etc.

    # Let the final try actually throw
    return func()


def load_base_image_tar_file(tar_file: Path):
    """
    Load the filesystem in the tar file into the podman repo.
    It will be available to subsequent commands using the associated tag
    """
    cmd = f"podman image load --quiet --input {tar_file}"
    invoke.run(cmd)


def arrange_component_files(context_dir, component_files):
    """Add component files into the context directory by copying them to their defined paths."""
    for component_file in component_files:
        source_file, install_target = component_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        install_target = os.path.join(context_dir, install_target)
        os.makedirs(os.path.dirname(install_target), exist_ok=True)
        shutil.copy(source_file, install_target)


def build_container(build_args: List[str],
                    context_dir: str,
                    dockerfile: str,
                    image_tag: str,
                    base_image_override: Optional[BaseImageOverride]) -> str:
    """Run container build command with given args. Return the given tag."""
    assert image_tag and context_dir, "Arguments can not be empty"

    build_arg_strings = [f"--build-arg \"{v}\"" for v in build_args]
    build_arg_strings_joined = ' '.join(build_arg_strings)

    cmd = "podman "
    cmd += "build "
    cmd += f"-t {image_tag} "
    cmd += f"{build_arg_strings_joined} "
    cmd += "--no-cache "

    if base_image_override:
        load_base_image_tar_file(base_image_override.image_file)
        # Override the first FROM statement - grabs it from local cache
        cmd += f"--from {base_image_override.image_tag} "

    # Set timestamp for all files for determinism
    cmd += "--timestamp 0 "

    if dockerfile:
        cmd += f"-f {dockerfile} "

    # Context must go last
    cmd += f"{context_dir}"
    print(cmd)
    def build_func():
        invoke.run(cmd)   # Throws on failure
    retry(build_func)
    return image_tag

def export_container_filesystem(image_tag: str,
                                destination_tar_filename: str):
    """
    Export the filesystem from an image.
    Creates container - but does not start it, avoiding timestamp and other determinism issues.
    """
    container_name = image_tag + "_container"
    invoke.run(f"podman create --name {container_name} {image_tag}")
    invoke.run(f"podman export -o {destination_tar_filename} {container_name}")
    invoke.run("sync")
    invoke.run(f"podman container rm -f {container_name}")


def resolve_file_args(context_dir: str, file_build_args: List[str]) -> List[str]:
    result = list()
    for arg in file_build_args:
        chunks = arg.split("=")
        if len(chunks) != 2:
            raise RuntimeError(f"File build arg '{arg}' is not valid")
        (name, pathname) = chunks

        path = Path(context_dir) / pathname

        with open(path, 'r') as f:
            value = f.readline().strip()
            result.append(f"{name}={value}")

    return result


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-d",
        "--dockerfile",
        type=str,
        default="",
        help="Name of the Dockerfile to build.",
    )

    parser.add_argument("-o", "--output", help="Target (tar) file to write to", type=str)

    parser.add_argument(
        "--build-arg",
        metavar="BUILD-ARG",
        dest="build_args",
        type=str,
        action="append",
        help="""Args to pass to Docker as build time variables. Each argument
                should be of the form VARIABLE=value. Can be specified multiple
                times.""",
    )

    parser.add_argument(
        "--file-build-arg",
        metavar="FILE-BUILD-ARG",
        dest="file_build_args",
        type=str,
        action="append",
        help="""File backed args to pass to Docker as build time variables.
                Each argument should be of the form VARIABLE=/path/to/file,
                where each file contains a single line value. Can be specified
                multiple times.""",
    )

    parser.add_argument(
        "--context-file",
        dest="context_files",
        type=str,
        action="append",
        help="Files to drop directly into the build context.",
        required=True
    )

    parser.add_argument(
        "--component-file",
        dest="component_files",
        type=str,
        action="append",
        help="Files to include in rootfs; expects list of sourcefile:targetfile",
        required=True
    )

    parser.add_argument(
        "--base-image-tar-file",
        help="Override the base image used by 'podman build'. The 'FROM' line in the target Dockerfile will be ignored",
        default=None,
        type=str)

    # Need the image tag to identify the right image.
    # `podman load` puts the image into the local image registry directly and labels it with the image tag used during `podman build`
    parser.add_argument(
        "--base-image-tar-file-tag",
        help="Tag given to the container image during 'podman build'. Required if --base-image-tar-file is used.",
        default=None,
        type=str)

    return parser.parse_args()


def main():
    args = get_args()

    destination_tar_filename = args.output
    build_args = list(args.build_args or [])

    # NOTE: /usr/bin/nsenter is required to be on $PATH for this version of
    # podman (no longer in latest version). bazel strips this out - add it back
    # manually, for now.
    os.environ["PATH"] = ":".join([x for x in [os.environ.get("PATH"), "/usr/bin"] if x is not None])

    image_tag = str(uuid.uuid4()).split('-')[0]
    context_files = args.context_files
    component_files = args.component_files

    context_dir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", context_dir], check=True))

    # Add all context files directly into dir
    for context_file in context_files:
        shutil.copy(context_file, context_dir)

    # Fill context with remaining component files from map
    arrange_component_files(context_dir, component_files)

    # Bazel can't read files. (: Resolve them here, instead.
    if args.file_build_args:
        resolved_file_args = resolve_file_args(context_dir, args.file_build_args)
        build_args.extend(resolved_file_args)

    # Override the base image with a local tar file?
    def only_one_defined(a,b) -> bool:
        return (a and not b) or (b and not a)
    assert not only_one_defined(args.base_image_tar_file, args.base_image_tar_file_tag), \
        "Please specify BOTH --base-image-tar-file* flags"

    base_image_override = None
    if args.base_image_tar_file:
        base_image_override = BaseImageOverride(Path(args.base_image_tar_file),
                                                args.base_image_tar_file_tag)

    build_container(build_args,
                    context_dir,
                    args.dockerfile,
                    image_tag,
                    base_image_override)

    export_container_filesystem(image_tag, destination_tar_filename)

    invoke.run(f"podman image rm -f {image_tag}")


if __name__ == "__main__":
    main()
