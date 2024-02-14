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
import uuid
from typing import Callable, List, TypeVar

import configargparse
import invoke


# We have yet to see the heisenbug with rootless builds, but build in a
# unique directory just in case.
TMP_ROOT = tempfile.mkdtemp()
TMP_RUNROOT = tempfile.mkdtemp()
atexit.register(lambda: cleanup())

# storage-opt is required when using `--root` as all other values from config are cleared
CONTAINER_COMMAND = f"podman --root {TMP_ROOT} --storage-opt=overlay.mount_program=/usr/bin/fuse-overlayfs --runroot {TMP_RUNROOT} "

def cleanup():
    # Use podman to cleanup first to avoid permission issues on the temp folders
    invoke.run(f"{CONTAINER_COMMAND} system reset -f")
    invoke.run(f"rm -rf {TMP_ROOT} {TMP_RUNROOT}")

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


def build_container(build_args: List[str],
                    context_dir: str,
                    dockerfile: str,
                    image_tag: str,
                    no_cache: bool) -> str:
    """Run container build command with given args. Return the given tag."""
    assert image_tag and context_dir, "Arguments can not be empty"

    build_arg_strings = [f"--build-arg {v}" for v in build_args]
    build_arg_strings_joined = ' '.join(build_arg_strings)

    cmd = f"{CONTAINER_COMMAND} "
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
    invoke.run(f"{CONTAINER_COMMAND} create --name {container_name} {image_tag}")
    invoke.run(f"{CONTAINER_COMMAND} export -o {destination_tar_filename} {container_name}")
    invoke.run("sync")
    invoke.run(f"{CONTAINER_COMMAND} container rm {container_name}")


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
    context_dir = args.context_dir
    no_cache = args.no_cache

    # Bazel can't read files. (: Resolve them here, instead.
    if args.file_build_args:
        resolved_file_args = resolve_file_args(context_dir, args.file_build_args)
        build_args.extend(resolved_file_args)

    build_container(build_args,
                    context_dir,
                    args.dockerfile,
                    image_tag,
                    no_cache)

    export_container_filesystem(image_tag, destination_tar_filename)

    remove_image(image_tag)


if __name__ == "__main__":
    main()
