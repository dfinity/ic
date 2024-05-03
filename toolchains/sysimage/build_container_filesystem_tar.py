#!/usr/bin/env python3
#
# Build a container image and extract the single flattened filesystem into a tar file.
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, TypeVar

import configargparse
import invoke
from container_utils import (
    generate_container_command,
    path_owned_by_root,
    process_temp_sys_dir_args,
    remove_image,
    take_ownership_of_file,
)


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


def load_base_image_tar_file(container_cmd: str, tar_file: Path):
    """
    Load the filesystem in the tar file into the podman repo.
    It will be available to subsequent commands using the associated tag
    """
    cmd = f"{container_cmd} image load --quiet --input {tar_file}"
    invoke.run(cmd)


def arrange_rootfs_files(context_dir, rootfs_files):
    """Add rootfs files into the context directory by copying them to their defined paths."""
    for rootfs_file in rootfs_files:
        source_file, install_target = rootfs_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        install_target = os.path.join(context_dir, install_target)
        os.makedirs(os.path.dirname(install_target), exist_ok=True)
        shutil.copy(source_file, install_target)


def build_container(container_cmd: str,
                    build_args: List[str],
                    context_dir: str,
                    dockerfile: str,
                    image_tag: str,
                    no_cache: bool,
                    base_image_override: Optional[BaseImageOverride]) -> str:
    """Run container build command with given args. Return the given tag."""
    assert image_tag and context_dir, "Arguments can not be empty"

    build_arg_strings = [f"--build-arg \"{v}\"" for v in build_args]
    build_arg_strings_joined = ' '.join(build_arg_strings)

    cmd = f"{container_cmd} "
    cmd += "build "
    cmd += f"-t {image_tag} "
    cmd += f"{build_arg_strings_joined} "

    # Rebuild layers instead of using cached ones.
    if no_cache:
        cmd += "--no-cache "

    if base_image_override:
        load_base_image_tar_file(container_cmd, base_image_override.image_file)
        # Override the first FROM statement - grabs it from local cache
        cmd += f"--from {base_image_override.image_tag} "

    # Set timestamp for all files for determinism
    cmd += "--timestamp 0 "

    if dockerfile:
        cmd += f"-f {dockerfile} "

    # Context must go last
    cmd += f"{context_dir} "
    print(cmd)
    def build_func():
        invoke.run(cmd)   # Throws on failure
    retry(build_func)
    return image_tag


def export_container_filesystem(container_cmd: str,
                                image_tag: str,
                                destination_tar_filename: str):
    """
    Export the filesystem from an image.
    Creates container - but does not start it, avoiding timestamp and other determinism issues.
    """
    container_name = image_tag + "_container"
    invoke.run(f"{container_cmd} create --name {container_name} {image_tag}")
    invoke.run(f"{container_cmd} export -o {destination_tar_filename} {container_name}")
    invoke.run("sync")
    invoke.run(f"{container_cmd} container rm {container_name}")

    destination_tar_path = Path(destination_tar_filename)
    # Using sudo w/ podman requires changing permissions on the output tar file (not the tar contents)
    assert path_owned_by_root(destination_tar_path), \
        f"'{destination_tar_path}' not owned by root. Remove this and the next line."
    take_ownership_of_file(destination_tar_path)


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


def generate_image_tag(base: str) -> str:
    # Image tags need to be unique and follow a specific format
    # See the (unwieldy) format spec:
    # https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests
    # Replace disallowed chars with dashes
    return base.translate(str.maketrans({'/': '-', '.':'-', ':':'-'}))


def build_and_export(container_cmd: str,
                     build_args: List[str],
                     context_dir: str,
                     dockerfile: str,
                     image_tag: str,
                     no_cache: bool,
                     base_image_override: Optional[BaseImageOverride],
                     destination_tar_filename: str) -> None:

    build_container(container_cmd,
                    build_args,
                    context_dir,
                    dockerfile,
                    image_tag,
                    no_cache,
                    base_image_override)

    export_container_filesystem(container_cmd,
                                image_tag,
                                destination_tar_filename)




def get_args():
    parser = configargparse.ArgumentParser()

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
        "--rootfs-file",
        dest="rootfs_files",
        type=str,
        action="append",
        help="Files to include in rootfs; expects list of sourcefile:targetfile",
        required=True
    )

    parser.add_argument(
        "--config-file",
        is_config_file=True,
        help='Config file path'
    )

    parser.add_argument(
        "--no-cache",
        help="By default the container builds using the image layer cache. Turn this on to prevent using the cache. Cache usage causes instability with parallel builds. It can be mitigated by addressing at a layer above this.",
        default=False,
        action="store_true"
    )

    parser.add_argument(
        "--temp-container-sys-dir",
        help="Container engine (podman) will use the specified dir to store its system files. It will remove the files before exiting.",
        type=str,
    )

    parser.add_argument(
        "--tmpfs-container-sys-dir",
        help="Create and mount a tmpfs to store its system files. It will be unmounted before exiting.",
        default=False,
        action="store_true"
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

    # Use the unique destination filename as the image tag.
    image_tag = generate_image_tag(destination_tar_filename)
    context_files = args.context_files
    rootfs_files = args.rootfs_files
    no_cache = args.no_cache
    temp_sys_dir = process_temp_sys_dir_args(args.temp_container_sys_dir, args.tmpfs_container_sys_dir)

    context_dir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", context_dir], check=True))

    # Add all context files directly into dir
    for context_file in context_files:
        shutil.copy(context_file, context_dir)

    # Fill context with remaining rootfs files from map
    arrange_rootfs_files(context_dir, rootfs_files)

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

    container_cmd = generate_container_command("sudo podman ", temp_sys_dir)
    build_and_export(container_cmd,
                     build_args,
                     context_dir,
                     args.dockerfile,
                     image_tag,
                     no_cache,
                     base_image_override,
                     destination_tar_filename)
    remove_image(container_cmd, image_tag) # No harm removing if in the tmp dir


if __name__ == "__main__":
    main()
