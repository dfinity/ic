import logging
import os
import shutil
from os import environ
from os import getenv
from os import path
from typing import Optional

from ci import cwd
from ci import ENV
from ci import flatten
from ci import mkdir_p
from ci import sh
from ci import show_sccache_stats

BIN_CANISTERS = [
    "cycles-minting-canister",
    "genesis-token-canister",
    "governance-canister",
    "governance-mem-test-canister",
    "ic-nervous-system-common-test-canister",
    "identity-canister",
    "inter_canister_error_handling",
    "json",
    "ledger-archive-node-canister",
    "ledger-canister",
    "mem-utils-test-canister",
    "memory-test-canister",
    "nan_canonicalized",
    "nns-ui-canister",
    "panics",
    "pmap_canister",
    "registry-canister",
    "response-payload-test-canister",
    "root-canister",
    "sns-governance-canister",
    "sns-root-canister",
    "sns-test-dapp-canister",
    "stable",
    "statesync-test-canister",
    "test-notified",
    "time",
    "upgrade-test-canister",
    "wasm",
    "xnet-test-canister",
]
LIB_CANISTERS = ["http_counter"]

# message max size is 3MB on system subnets and 2MB on other subnets
CANISTERS_MAX_SIZE_IN_BYTES = {
    "ledger-canister.wasm": 1_900_000,
    "ledger-canister_notify-method.wasm": 1_900_000,
    "cycles-minting-canister.wasm": 2_500_000,
    "genesis-token-canister.wasm": 2_500_000,
    "governance-canister.wasm": 2_500_000,
    "governance-mem-test-canister.wasm": 2_500_000,
    "registry-canister.wasm": 3_500_000,
    "root-canister.wasm": 1_500_000,
    "sns-governance-canister.wasm": 1_500_000,
    "sns-governance-canister_test.wasm": 1_500_000,
    "sns-root-canister.wasm": 1_500_000,
}

CANISTER_BUILD_PROFILE = "canister-release"

CANISTER_COPY_LIST = {"cow_safety.wasm": "rs/tests/src", "counter.wat": "rs/workload_generator/src"}

artifact_ext = getenv("ARTIFACT_EXT", "")
default_artifacts_dir = f"{ENV.top}/artifacts/canisters{artifact_ext}"


def _optimize_wasm(artifacts_dir, bin):
    src_filename = f"{ENV.cargo_target_dir}/wasm32-unknown-unknown/{CANISTER_BUILD_PROFILE}/{bin}.wasm"
    out_filename = f"{artifacts_dir}/{bin}.wasm"
    if path.exists(src_filename):
        sh("ic-cdk-optimizer", "-o", out_filename, src_filename)
        return out_filename
    else:
        raise Exception(f"ERROR: target canister Wasm binary does not exist: {src_filename}")


def _build_with_features(bin_name, features, target_bin_name: Optional[str] = None):
    target_bin_name = f"{bin_name}_{features}" if target_bin_name is None else target_bin_name
    sh(
        "cargo",
        "build",
        "--target",
        "wasm32-unknown-unknown",
        "--profile",
        CANISTER_BUILD_PROFILE,
        "--bin",
        bin_name,
        "--features",
        features,
    )
    os.rename(
        f"{ENV.cargo_target_dir}/wasm32-unknown-unknown/{CANISTER_BUILD_PROFILE}/{bin_name}.wasm",
        f"{ENV.cargo_target_dir}/wasm32-unknown-unknown/{CANISTER_BUILD_PROFILE}/{target_bin_name}.wasm",
    )


def _check_canisters_size(artifacts_dir=default_artifacts_dir):
    for can, max_size_in_bytes in CANISTERS_MAX_SIZE_IN_BYTES.items():
        can_path = f"{artifacts_dir}/{can}"
        can_size = path.getsize(can_path)
        if can_size > max_size_in_bytes:
            logging.error(
                f"Size of the canister {can} is {can_size} which is above the maximum allowed {max_size_in_bytes}"
            )
            exit(1)


def run(artifacts_dir=default_artifacts_dir):
    mkdir_p(artifacts_dir)

    # TODO: get rid of this usage of git revision
    environ["VERSION"] = ENV.build_id

    # Make sure git-related non-determinism does't get through.
    if ENV.is_gitlab:
        date = sh("date", capture=True)
        sh(
            "git",
            "-c",
            "user.name=Gitlab CI",
            "-c",
            "user.email=infra+gitlab-automation@dfinity.org",
            "commit",
            "--allow-empty",
            "-m",
            f"Non-determinism detection commit at {date}",
        )

    with cwd("rs"):
        sh(
            "cargo",
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--profile",
            CANISTER_BUILD_PROFILE,
            "--bin",
            "ledger-archive-node-canister",
        )
        # We need to build the ledger archive node canister _before_ we build the ledger
        # canister because the latter needs to include the Wasm module of the former.
        # The ledger canister expects the path to the ledger archive Wasm to be passed as
        # a compile-time environment variable.
        ledger_archive_path = _optimize_wasm(artifacts_dir, "ledger-archive-node-canister")
        environ["LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH"] = ledger_archive_path

        _build_with_features("ledger-canister", "notify-method")
        _build_with_features("governance-canister", "test")
        _build_with_features("sns-governance-canister", "test")

        sh(
            "cargo",
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--profile",
            CANISTER_BUILD_PROFILE,
            *flatten([["--bin", b] for b in BIN_CANISTERS]),
        )

        sh(
            "cargo",
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--profile",
            CANISTER_BUILD_PROFILE,
            *flatten([["--package", p] for p in LIB_CANISTERS]),
        )

        sh(
            "cargo",
            "run",
            "--bin",
            "lifeline",
            "--",
            f"{ENV.cargo_target_dir}/wasm32-unknown-unknown/{CANISTER_BUILD_PROFILE}/lifeline.wasm",
        )

    logging.info("Building of Wasm canisters finished")

    for canister in (
        [
            "ledger-canister_notify-method",
            "governance-canister_test",
            "sns-governance-canister_test",
            "lifeline",
        ]
        + BIN_CANISTERS
        + LIB_CANISTERS
    ):
        _optimize_wasm(artifacts_dir, canister)

    for can, filepath in CANISTER_COPY_LIST.items():
        src_filename = f"{filepath}/{can}"
        if can.endswith(".wasm"):
            sh("ic-cdk-optimizer", "-o", f"{artifacts_dir}/{can}", f"{ENV.top}/{src_filename}")
        elif can.endswith(".wat"):
            shutil.copyfile(f"{ENV.top}/{src_filename}", f"{artifacts_dir}/{can}")
        else:
            logging.error(f"unknown (not .wat or .wasm) canister type: {src_filename}")
            exit(1)

    _check_canisters_size(artifacts_dir=default_artifacts_dir)

    sh(f"sha256sum {artifacts_dir}/*", shell=True)
    sh(f"pigz -f --no-name {artifacts_dir}/*", shell=True)

    if ENV.is_gitlab:
        sh("gitlab-ci/src/artifacts/openssl-sign.sh", f"{ENV.top}/artifacts/canisters{artifact_ext}")

    show_sccache_stats()
