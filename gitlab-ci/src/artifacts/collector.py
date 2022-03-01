import logging
import multiprocessing
import os
import shutil
import tempfile
from os import path
from typing import List

from ci import cwd
from ci import ENV
from ci import log_section
from ci import mkdir_p
from ci import sh


def local(v: str) -> str:
    return path.join(ENV.top, "gitlab-ci/src/artifacts", v)


RUST_BINARIES = [
    "boundary-node-control-plane",
    "boundary-node-prober",
    "canister_sandbox",
    "e2e-test-driver",
    "ic-admin",
    "ic-btc-adapter",
    "ic-canister-http-adapter",
    "ic-consensus-pool-util",
    "ic-crypto-csp",
    "ic-cup-explorer",
    "ic-get-neuron-ids",
    "ic-nns-init",
    "ic-p8s-service-discovery",
    "ic-p8s-sd",
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


class Collector:
    """A script that collects a list of binaries, performs various transformations on them (see below), and puts them in `ARTIFACTS_DIR` so GitLab can detect and upload them."""

    artifacts_dir: str
    files: List[str]

    def __init__(
        self,
        artifacts_dir="artifacts/nix-release",
        files=RUST_BINARIES,
    ) -> None:
        self.artifacts_dir = artifacts_dir
        self.files = files

        self.temp = tempfile.mkdtemp()

    @classmethod
    def collect(cls, artifacts_dir="artifacts/nix-release", files=RUST_BINARIES):
        with log_section("Click here to see artifact processing output"):
            cls(artifacts_dir, files).run()

    def run(self):
        with cwd(ENV.top):
            # This is the directory GitLab searches for artifacts once the job has completed
            self.out_dir = path.join(ENV.top, self.artifacts_dir)
            mkdir_p(self.out_dir)

            p = multiprocessing.Pool()
            try:
                p.map(self._process_one, self.files)
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                raise

            if "malicious" in self.artifacts_dir:
                return

            if path.exists("/openssl/private.pem"):
                sh(local("openssl-sign.sh"), self.out_dir)
            else:
                logging.warn("/openssl/private.pem doesn't exist, so these artifacts won't be signed")

    def _process_one(self, binary: str):
        """
        Things we do in here:.

        * Strip debuginfo from the binaries (using objcopy or strip)
        * On Linux, run patchelf, so binaries built in nix-shell can run on other systems
        * On Darwin, fix dylibs, which accomplishes the same goal as the previous bullet point
        * If REALLY_STRIP is set, strip Nix store references and fail if there are any we don't recognize (disabled right now because the nix shell path ends up in every rpath for some reason)
        """
        src_path = path.join(ENV.target_dir, ENV.build_target, "release", binary)
        bin_path = path.join(self.temp, binary)

        if not os.access(src_path, os.R_OK):
            logging.info(f"Binary not found at {src_path}")
            return

        shutil.copyfile(src_path, bin_path)

        if binary not in DONT_STRIP:
            self._strip(bin_path)

        self._adjust_paths(bin_path)
        self._strip_refs(bin_path)

        sh("pigz", "-c", "--no-name", bin_path, pipe_to=path.join(self.out_dir, f"{binary}.gz"))

    def _strip(self, in_path: str):
        if ENV.is_linux:
            sh("objcopy", "-D", "--strip-debug", in_path)
        elif ENV.is_macos:
            sh("strip", "-S", in_path)

    def _adjust_paths(self, in_path: str):
        if ENV.is_linux:
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
                env={"allowedStrippedRefs": " ".join(STRIP_REFS[ENV.build_target])},
            )
