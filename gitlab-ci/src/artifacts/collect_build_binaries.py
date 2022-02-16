#!/usr/bin/env python3
import argparse
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
from multiprocessing import Pool
from os import path
from typing import Literal
from typing import Optional
from typing import overload

DEFAULT_BINARIES = [
    "boundary-node-control-plane",
    "canister_sandbox",
    "e2e-test-driver",
    "ic-admin",
    "ic-btc-adapter",
    "ic-consensus-pool-util",
    "ic-crypto-csp",
    "ic-cup-explorer",
    "ic-get-neuron-ids",
    "ic-nns-init",
    "ic-p8s-service-discovery",
    "ic-prep",
    "ic-regedit",
    "ic-replay",
    "ic-rosetta-api",
    "ic-starter",
    "ic-test-bin",
    "ic-workload-generator",
    "orchestrator",
    "prod-test-driver",
    "replica",
    "sandbox_launcher",
    "state-tool",
    "system-tests",
    "vsock_agent",
]

DONT_STRIP = ["replica", "canister_sandbox"]

STRIP_REFS = {
    "x86_64-unknown-linux-gnu": [
        "*-glibc-*",
        "*-gcc-*",
        "*-openssl-*",
        "*-libidn2-*",
        "*-binutils-*",
        "*-crates-io",
    ],
    "x86_64-apple-darwin": ["*-crates-io", "*-swift-corefoundation", "*-openssl-*"],
}

# "realpath" actually does not return the correct path after a chdir
HERE = path.realpath(__file__)


def local(v: str) -> str:
    return path.join(path.dirname(HERE), v)


@overload
def sh(*popenargs, pipe_to: Optional[str] = None, capture: Literal[True], **kwargs) -> str:
    ...


@overload
def sh(*popenargs, pipe_to: Optional[str] = None, capture: bool = False, **kwargs) -> None:
    ...


def sh(*popenargs, pipe_to: Optional[str] = None, capture: bool = False, **kwargs):
    cmdline = list(popenargs)
    cmdline_extra = ""

    assert (not capture) or (pipe_to is None), "the `capture` and `pipe_to` arguments are mutually exclusive"

    if pipe_to is not None:
        kwargs["stdout"] = open(pipe_to, "w")
        cmdline_extra = f" > {pipe_to}"

    print(f"$ {shlex.join(cmdline)}{cmdline_extra}")

    if capture:
        return subprocess.run(cmdline, text=True, stdout=subprocess.PIPE, **kwargs).stdout.strip()
    else:
        subprocess.run(cmdline, **kwargs).check_returncode()


def getenv(v: str) -> str:
    s = os.environ.get(v)
    if s is None:
        raise RuntimeError(f"variable {v} is not set")
    return s


class Collector:
    """A script that collects a list of binaries, performs various transformations on them (see below), and puts them in ARTIFACTS_DIR so GitLab can detect and upload them."""

    def __init__(self) -> None:
        """__init__ inits."""
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "artifacts_dir",
            nargs="?",
            metavar="ARTIFACTS_DIR",
            default="artifacts/nix-release",
            help="Where to place processed binaries",
        )
        parser.add_argument(
            "files",
            metavar="BINARY",
            nargs="*",
            help="Build artifact. If none are provided, uses a default list",
            default=DEFAULT_BINARIES,
        )

        self.args = parser.parse_args()
        self.build_target = getenv("CARGO_BUILD_TARGET")
        self.target_dir = getenv("CARGO_TARGET_DIR")
        self.is_linux = self.build_target == "x86_64-unknown-linux-gnu"
        self.is_macos = self.build_target == "x86_64-apple-darwin"

        self.temp = tempfile.mkdtemp()

        if not self.is_linux and not self.is_macos:
            raise RuntimeError(f"Unrecognized build target {self.build_target}, unable to continue")

    def run(self):
        """Run runs the script."""
        project_dir = sh("git", "rev-parse", "--show-toplevel", capture=True)
        os.chdir(project_dir)

        # This is the directory GitLab searches for artifacts once the job has completed
        self.out_dir = path.join(project_dir, self.args.artifacts_dir)
        pathlib.Path(self.out_dir).mkdir(parents=True, exist_ok=True)

        Pool().map(self._process_one, self.args.files)

        if "malicious" in self.args.artifacts_dir:
            return

        if path.exists("/openssl/private.pem"):
            sh(local("openssl-sign.sh"), self.out_dir)
        else:
            print("WARNING: /openssl/private.pem doesn't exist, so these artifacts won't be signed")

    def _process_one(self, binary: str):
        """
        Things we do in here:.

        * Strip debuginfo from the binaries (using objcopy or strip)
        * On Linux, run patchelf, so binaries built in nix-shell can run on other systems
        * On Darwin, fix dylibs, which accomplishes the same goal as the previous bullet point
        * If REALLY_STRIP is set, strip Nix store references and fail if there are any we don't recognize (disabled right now because the nix shell path ends up in every rpath for some reason)
        """
        src_path = path.join(self.target_dir, self.build_target, "release", binary)
        bin_path = path.join(self.temp, binary)

        if not os.access(src_path, os.R_OK):
            print(f"Binary not found at {src_path}")
            return

        shutil.copyfile(src_path, bin_path)

        if binary not in DONT_STRIP:
            self._strip(bin_path)

        self._adjust_paths(bin_path)
        self._strip_refs(bin_path)

        sh("gzip", "-c", "--no-name", bin_path, pipe_to=path.join(self.out_dir, f"{binary}.gz"))

    def _strip(self, in_path: str):
        if self.is_linux:
            sh("objcopy", "-D", "--strip-debug", in_path)
        elif self.is_macos:
            sh("strip", "-S", in_path)

    def _adjust_paths(self, in_path: str):
        if self.is_linux:
            sh(
                "patchelf",
                "--remove-rpath",
                "--set-interpreter",
                "/lib64/ld-linux-x86-64.so.2",
                in_path,
            )
        else:
            sh(local("relocate-darwin-syslibs.sh"), in_path)

    def _strip_refs(self, in_path: str):
        if "REALLY_STRIP" in os.environ:
            sh(
                local("strip-references.sh"),
                in_path,
                env={"allowedStrippedRefs": " ".join(STRIP_REFS[self.build_target])},
            )


if __name__ == "__main__":
    Collector().run()
