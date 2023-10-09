#!/usr/bin/env python3
#
# Build a container image and extract the single flattened filesystem into a tar file.
from __future__ import annotations

import atexit
import os
import pathlib
import sys
import tempfile
import time
from typing import Callable, List, Optional, TypeVar

import configargparse
import invoke
from reproducibility import print_artifact_info

CONTAINER_COMMAND = "sudo podman "
SYS_DIR_PREFIX = "podman_sys_dir_"
DEFAULT_TMP_PREFIX = "/tmp"

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


def build_container(container_cmd: str,
                    build_args: List[str],
                    context_dir: str,
                    dockerfile: str,
                    image_tag: str,
                    no_cache: bool) -> str:
    """Run container build command with given args. Return the given tag."""
    assert image_tag and context_dir, "Arguments can not be empty"

    build_arg_strings = [f"--build-arg {v}" for v in build_args]
    build_arg_strings_joined = ' '.join(build_arg_strings)

    cmd = f"{container_cmd} "
    cmd += "build "
    cmd += f"-t {image_tag} "
    cmd += f"{build_arg_strings_joined} "

    # Rebuild layers instead of using cached ones.
    if no_cache:
        cmd += "--no-cache "

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

    # Using sudo w/ podman requires changing permissions on the output tar file (not the tar contents)
    file_owner_uid = os.stat(destination_tar_filename).st_uid
    root_uid = 0
    assert file_owner_uid == root_uid, \
        f"'{destination_tar_filename}' not owned by root. Remove this and the next code block."

    current_user = invoke.run("whoami").stdout.strip()
    invoke.run(f"sudo chown {current_user} {destination_tar_filename}")
    invoke.run(f"sudo chgrp {current_user} {destination_tar_filename}")


def remove_image(image_tag: str):
    invoke.run(f"{CONTAINER_COMMAND} image rm -f {image_tag}")


def resolve_file_args(context_dir: str, file_build_args: List[str]) -> List[str]:
    result = list()
    for arg in file_build_args:
        chunks = arg.split("=")
        if len(chunks) != 2:
            raise RuntimeError(f"File build arg '{arg}' is not valid")
        (name, pathname) = chunks

        path = pathlib.Path(context_dir) / pathname

        with open(path, 'r') as f:
            value = f.readline().strip()
            result.append(f"{name}={value}")

    return result


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
        "--context-dir",
        type=str,
        help="Directory to be used as docker build context.",
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

    return parser.parse_args()


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
                     destination_tar_filename: str) -> None:

    build_container(container_cmd,
                    build_args,
                    context_dir,
                    dockerfile,
                    image_tag,
                    no_cache)

    export_container_filesystem(container_cmd,
                                image_tag,
                                destination_tar_filename)


def make_tmpfs(base_dir: str = DEFAULT_TMP_PREFIX) -> str:
    """
    Mount a tmpfs volume in a subdirectory of the given `base_dir`.
    Auto unmount at exit.

    This seems to work across environments:
      - CI - running K8S containerd runners
      - gitlab-ci/container/container-run.sh

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
    assert not (temp_container_sys_dir and tmpfs_container_sys_dir), \
        "temp_container_sys_dir and tmpfs_container_sys_dir flags are mutually exclusive"
    if temp_container_sys_dir:
        return temp_container_sys_dir

    if tmpfs_container_sys_dir:
        return make_tmpfs()

    return None


def main():
    args = get_args()

    destination_tar_filename = args.output
    build_args = list(args.build_args or [])

    # Use the unique destination filename as the image tag.
    image_tag = generate_image_tag(destination_tar_filename)
    context_dir = args.context_dir
    no_cache = args.no_cache
    temp_sys_dir = process_temp_sys_dir_args(args.temp_container_sys_dir, args.tmpfs_container_sys_dir)

    # Bazel can't read files. (: Resolve them here, instead.
    if args.file_build_args:
        resolved_file_args = resolve_file_args(context_dir, args.file_build_args)
        build_args.extend(resolved_file_args)

    # Avoid repetition of args. Bind to a function
    def build_func(container_cmd):
        return build_and_export(container_cmd, build_args, context_dir, args.dockerfile, image_tag, no_cache, destination_tar_filename)

    if temp_sys_dir:
        container_sys_dir = tempfile.mkdtemp(prefix=SYS_DIR_PREFIX, dir=temp_sys_dir)
        container_run_dir = tempfile.mkdtemp(prefix=SYS_DIR_PREFIX, dir=temp_sys_dir)
        # podman runs via sudo, so the files have root uid/gid.
        # Use sudo to remove the files.
        atexit.register(lambda: invoke.run(f"sudo rm -rf {container_sys_dir} {container_run_dir}"))
        container_cmd = f"{CONTAINER_COMMAND} --root {container_sys_dir} --runroot {container_run_dir} "
        build_func(container_cmd)
    else:
        build_func(CONTAINER_COMMAND)
        remove_image(image_tag)

    print_artifact_info(destination_tar_filename)


if __name__ == "__main__":
    main()
