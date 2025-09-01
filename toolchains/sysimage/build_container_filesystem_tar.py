#!/usr/bin/env python3
#
# Build a container image and extract the single flattened filesystem into a tar file.
from __future__ import annotations

import argparse
import atexit
import os
import shutil
import signal
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import invoke
from loguru import logger as log

from toolchains.sysimage.utils import (
    purge_podman,
    remove_image,
)


@dataclass(frozen=True)
class BaseImageOverride:
    image_file: Path
    image_tag: str

    def __post_init__(self):
        assert self.image_tag is not None
        assert self.image_file is not None
        assert self.image_file.exists()


def load_base_image_tar_file(container_cmd: str, tar_file: Path):
    """
    Load the filesystem in the tar file into the podman repo.
    It will be available to subsequent commands using the associated tag
    """
    cmd = f"{container_cmd} image load --quiet --input {tar_file}"
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


def build_container(
    container_cmd: str,
    build_args: List[str],
    context_dir: str,
    dockerfile: str,
    image_tag: str,
    no_cache: bool,
    base_image_override: Optional[BaseImageOverride],
) -> str:
    """Run container build command with given args. Return the given tag."""
    assert image_tag and context_dir, "Arguments can not be empty"

    build_arg_strings = [f'--build-arg "{v}"' for v in build_args]
    build_arg_strings_joined = " ".join(build_arg_strings)

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

    invoke.run(cmd)  # Throws on failure
    return image_tag


def export_container_filesystem(container_cmd: str, image_tag: str, destination_tar_filename: str):
    """
    Export the filesystem from an image.
    Creates container - but does not start it, avoiding timestamp and other determinism issues.
    """
    tempdir = tempfile.mkdtemp()
    tar_file = tempdir + "/temp.tar"
    fakeroot_statefile = tempdir + "/fakeroot.state"
    tar_dir = tempdir + "/tar"

    container_name = image_tag + "_container"
    invoke.run(f"{container_cmd} create --name {container_name} {image_tag}")
    invoke.run(f"{container_cmd} export -o {tar_file} {container_name}")
    invoke.run(f"mkdir -p {tar_dir}")
    invoke.run(f"fakeroot -s {fakeroot_statefile} tar xpf {tar_file} --same-owner --numeric-owner -C {tar_dir}")
    invoke.run(
        f"fakeroot -i {fakeroot_statefile} tar cf {destination_tar_filename} --numeric-owner --sort=name --exclude='run/*' -C {tar_dir} $(ls -A {tar_dir})"
    )
    invoke.run("sync")
    invoke.run(f"{container_cmd} container rm {container_name}")


def resolve_file_args(context_dir: str, file_build_args: List[str]) -> List[str]:
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


def generate_image_tag(base: str) -> str:
    # Image tags need to be unique and follow a specific format
    # See the (unwieldy) format spec:
    # https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests
    # Replace disallowed chars with dashes
    return base.translate(str.maketrans({"/": "-", ".": "-", ":": "-"})).lower()


def build_and_export(
    container_cmd: str,
    build_args: List[str],
    context_dir: str,
    dockerfile: str,
    image_tag: str,
    no_cache: bool,
    base_image_override: Optional[BaseImageOverride],
    destination_tar_filename: str,
) -> None:
    build_container(container_cmd, build_args, context_dir, dockerfile, image_tag, no_cache, base_image_override)

    export_container_filesystem(container_cmd, image_tag, destination_tar_filename)


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
        required=True,
    )

    parser.add_argument(
        "--component-file",
        dest="component_files",
        type=str,
        action="append",
        help="Files to include in rootfs; expects list of sourcefile:targetfile",
        required=True,
    )

    parser.add_argument(
        "--no-cache",
        help="By default the container builds using the image layer cache. Turn this on to prevent using the cache. Cache usage causes instability with parallel builds. It can be mitigated by addressing at a layer above this.",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--base-image-tar-file",
        help="Override the base image used by 'podman build'. The 'FROM' line in the target Dockerfile will be ignored",
        default=None,
        type=str,
    )

    # Need the image tag to identify the right image.
    # `podman load` puts the image into the local image registry directly and labels it with the image tag used during `podman build`
    parser.add_argument(
        "--base-image-tar-file-tag",
        help="Tag given to the container image during 'podman build'. Required if --base-image-tar-file is used.",
        default=None,
        type=str,
    )

    return parser.parse_args()


def main():
    args = get_args()

    destination_tar_filename = args.output
    build_args = list(args.build_args or [])

    # Use the unique destination filename as the image tag.
    image_tag = generate_image_tag(destination_tar_filename)
    context_files = args.context_files
    component_files = args.component_files
    no_cache = args.no_cache

    context_dir = tempfile.mkdtemp()

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
    def only_one_defined(a, b) -> bool:
        return (a and not b) or (b and not a)

    assert not only_one_defined(
        args.base_image_tar_file, args.base_image_tar_file_tag
    ), "Please specify BOTH --base-image-tar-file* flags"

    base_image_override = None
    if args.base_image_tar_file:
        base_image_override = BaseImageOverride(Path(args.base_image_tar_file), args.base_image_tar_file_tag)

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

    build_and_export(
        container_cmd,
        build_args,
        context_dir,
        args.dockerfile,
        image_tag,
        no_cache,
        base_image_override,
        destination_tar_filename,
    )
    remove_image(container_cmd, image_tag)  # No harm removing if in the tmp dir

    # tempfile cleanup is handled by proc_wrapper.sh


if __name__ == "__main__":
    main()
