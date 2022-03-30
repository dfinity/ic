#!/usr/bin/env python3
"""
A runner of farm-based system tests.
Essentially it is a wrapper around `prod-test-driver`, which executes test suites.
This script can be used both locally and on the CI.

Responsibilities:
- Download/extract artifacts and guest-os image.
- Generate ssh keys.
- Run the test driver.
- Push results to honeycomb.
- Send slack messages (for scheduled jobs) about the failed tests.

Typical example usage:

    ./run-system-tests.py --suite=pre_master
"""
import getpass
import gzip
import logging
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import requests

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(name)s:%(message)s")


RED = "\033[1;31m"
GREEN = "\033[1;32m"
NC = "\033[0m"


def run_help_command():
    # Help command is supposed to be run only locally.
    help_command = "/usr/bin/time cargo run --bin prod-test-driver -- --help"
    run_command(command=help_command)


def exit_with_log(msg: str) -> None:
    logging.error(f"{RED}{msg}{NC}")
    sys.exit(1)


def extract_artifacts(source_dir: str, dest_dir: str, delete_source_dir: bool, is_set_executable: bool) -> None:
    logging.info(f"Unzipping files in {source_dir} dir.")
    files_list = os.listdir(source_dir)
    for file in files_list:
        file_name = os.path.join(source_dir, file)
        if file_name.endswith(".gz"):
            with gzip.open(file_name, "rb") as f_in:
                # Take filename without extension.
                save_file = os.path.splitext(file_name)[0]
                with open(save_file, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    # Set executable attribute (chmod +x).
                    if is_set_executable:
                        st = os.stat(save_file)
                        os.chmod(save_file, st.st_mode | stat.S_IEXEC)
                    # Move the file after extraction (overwrite if exists).
                    shutil.move(save_file, os.path.join(dest_dir, os.path.basename(save_file)))
    if delete_source_dir:
        logging.info(f"Deleting source {source_dir} dir.")
        shutil.rmtree(source_dir, ignore_errors=True)


def replace_symbols(text: str, symbols_to_replace: List[str], replace_with: str) -> str:
    for ch in symbols_to_replace:
        text = text.replace(ch, replace_with)
    return text


def remove_folders(folders: List[str]) -> None:
    for folder in folders:
        logging.info(f"{RED}Removing directory {folder}.{NC}")
        shutil.rmtree(folder, ignore_errors=True)


def create_env_variables(is_local_run: bool, artifact_dir: str, ci_project_dir: str, tmp_dir: str) -> Dict:
    env = os.environ.copy()
    env["TMPDIR"] = tmp_dir
    env["IC_ROOT"] = ci_project_dir
    env["PATH"] = f"{artifact_dir}:" + env["PATH"]
    env["PATH"] = f"{ci_project_dir}/rs/tests:" + env["PATH"]
    if not is_local_run:
        env["XNET_TEST_CANISTER_WASM_PATH"] = f"{artifact_dir}/xnet-test-canister.wasm"
    slack_notify = f"{ci_project_dir}/gitlab-ci/src/notify_slack"
    if env.get("PYTHONPATH") is None:
        env.setdefault("PYTHONPATH", slack_notify)
    else:
        env["PYTHONPATH"] = f"{slack_notify}:" + env["PYTHONPATH"]
    return env


def get_ic_os_image_sha(img_base_url) -> Tuple[str, str]:
    img_url = f"{img_base_url}disk-img.tar.gz"
    img_sha256_url = f"{img_base_url}SHA256SUMS"
    result = requests.get(f"{img_sha256_url}")
    img_sha256 = result.text.split(" ")[0]
    return img_sha256, img_url


def run_command(command: str, env: Optional[Dict] = None) -> int:
    # Run shell subprocess with live stdout, stderr.
    process = subprocess.run(command, shell=True, env=env)
    return process.returncode


def generate_default_job_id() -> str:
    return f"{getpass.getuser()}-{socket.gethostname()}-{int(time.time())}"


def build_test_driver(shell_wrapper: str) -> int:
    test_driver_build_cmd = " ".join([shell_wrapper, "cargo build --bin prod-test-driver"])
    logging.info("Building prod-test-driver binary...")
    status_code = run_command(command=test_driver_build_cmd)
    return status_code


def main(runner_args: str, folders_to_remove: List[str], keep_tmp_artifacts_folder: bool) -> int:
    # From this path the script was started.
    base_path = os.getcwd()
    # Set path to the script path (in case script is launched from non-parent dir).
    current_path = Path(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(current_path.absolute())
    root_ic_dir = str(current_path.parent.parent.absolute())
    # Read all environmental variables.
    CI_PROJECT_DIR = os.getenv("CI_PROJECT_DIR", default=root_ic_dir)
    TEST_ES_HOSTNAMES = os.getenv("TEST_ES_HOSTNAMES", default=None)
    SHELL_WRAPPER = os.getenv("SHELL_WRAPPER", default="/usr/bin/time")
    SSH_KEY_DIR = os.getenv("SSH_KEY_DIR", default=None)
    IC_VERSION_ID = os.getenv("IC_VERSION_ID", default=None)
    JOB_ID = os.getenv("CI_JOB_ID", default=None)
    ADDITIONAL_ARGS = os.getenv("ADDITIONAL_ARGS", default="")
    CI_PARENT_PIPELINE_SOURCE = os.getenv("CI_PARENT_PIPELINE_SOURCE", default="")
    CI_PIPELINE_SOURCE = os.getenv("CI_PIPELINE_SOURCE", default="")
    ROOT_PIPELINE_ID = os.getenv("ROOT_PIPELINE_ID", default="")
    CI_JOB_URL = os.getenv("CI_JOB_URL", default="")
    CI_PROJECT_URL = os.getenv("CI_PROJECT_URL", default="")
    CI_COMMIT_SHA = os.getenv("CI_COMMIT_SHA", default="")
    CI_COMMIT_SHORT_SHA = os.getenv("CI_COMMIT_SHORT_SHA", default="")
    ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", default="")
    # Start set variables.
    is_local_run = JOB_ID is None
    use_locally_prebuilt_artifacts = ARTIFACT_DIR != ""
    # Handle relative ARTIFACT_DIR path.
    if is_local_run and not os.path.isabs(ARTIFACT_DIR):
        ARTIFACT_DIR = os.path.join(base_path, ARTIFACT_DIR)
    is_merge_request = CI_PARENT_PIPELINE_SOURCE == "merge_request_event"
    is_honeycomb_push = not is_local_run
    is_slack_notify = not is_local_run and CI_PIPELINE_SOURCE == "schedule"
    # End set variables.

    # Firstly, build the prod-test-driver binary.
    if is_local_run:
        return_code = build_test_driver(SHELL_WRAPPER)
        if return_code != 0:
            exit_with_log("Failed to build prod-test-driver bin.")

    if not is_local_run and use_locally_prebuilt_artifacts:
        exit_with_log("One can't use locally prebuilt artifacts on the CI.")

    logging.debug(
        f"is_local_run={is_local_run}, is_merge_request={is_merge_request}, "
        f"use_locally_prebuilt_artifacts={use_locally_prebuilt_artifacts}, is_honeycomb_push={is_honeycomb_push}, "
        f"is_slack_notify={is_slack_notify}"
    )

    if IC_VERSION_ID is None:
        exit_with_log(
            "You must specify GuestOS image version via IC_VERSION_ID. You have two options:\n1) To obtain a GuestOS "
            "image version for your commit, please push your branch to origin and create an MR. See "
            "http://go/guestos-image-version\n2) To obtain the latest GuestOS image version for origin/master (e.g., "
            "if your changes are withing ic/rs/tests), use the following command: "
            "ic/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master\nNote: this command is not "
            "guaranteed to be deterministic."
        )

    if TEST_ES_HOSTNAMES is None:
        logging.info("TEST_ES_HOSTNAMES variable is not set, using defaults.")
        TEST_ES_HOSTNAMES = ",".join(
            [
                "elasticsearch-node-0.testnet.dfinity.systems:443",
                "elasticsearch-node-1.testnet.dfinity.systems:443",
                "elasticsearch-node-2.testnet.dfinity.systems:443",
            ]
        )
    TEST_ES_HOSTNAMES = replace_symbols(text=TEST_ES_HOSTNAMES, symbols_to_replace=["`", "'", " "], replace_with="")

    IC_OS_DEV_IMG_SHA256, IC_OS_DEV_IMG_URL = get_ic_os_image_sha(
        f"https://download.dfinity.systems/ic/{IC_VERSION_ID}/guest-os/disk-img-dev/"
    )
    BOUNDARY_NODE_IMG_SHA256, BOUNDARY_NODE_IMG_URL = get_ic_os_image_sha(
        f"https://download.dfinity.systems/ic/{IC_VERSION_ID}/boundary-os/disk-img/"
    )

    if SSH_KEY_DIR is None:
        logging.info("SSH_KEY_DIR variable is not set, generating keys.")
        SSH_KEY_DIR = tempfile.mkdtemp()
        folders_to_remove.append(SSH_KEY_DIR)
        gen_key_command = f"ssh-keygen -t ed25519 -N '' -f {SSH_KEY_DIR}/admin"
        gen_key_returncode = run_command(command=gen_key_command)
        if gen_key_returncode == 0:
            logging.info("ssh keys generated successfully.")
        else:
            exit_with_log("Failed to generate ssh keys.")

    if is_local_run:
        JOB_ID = generate_default_job_id()
        RUN_CMD = "cargo"
        ADDITIONAL_ARGS = "run --bin prod-test-driver --"
        artifacts_tmp_dir = tempfile.mkdtemp(prefix="tmp_artifacts_")
        if not keep_tmp_artifacts_folder:
            folders_to_remove.append(artifacts_tmp_dir)
        _tmp = f"{artifacts_tmp_dir}/artifacts"
        if use_locally_prebuilt_artifacts:
            logging.info(f"Copying prebuilt artifacts from {ARTIFACT_DIR} to {_tmp}")
            shutil.copytree(ARTIFACT_DIR, _tmp)
        ARTIFACT_DIR = _tmp
        results_tmp_dir = tempfile.mkdtemp()
        folders_to_remove.append(results_tmp_dir)
        RESULT_FILE = f"{results_tmp_dir}/test-results.json"
        SUMMARY_ARGS = f"--test_results {RESULT_FILE} --verbose "
    else:
        ARTIFACT_DIR = f"{CI_PROJECT_DIR}/artifacts"
        RUN_CMD = f"{ARTIFACT_DIR}/prod-test-driver"
        RESULT_FILE = f"{CI_PROJECT_DIR}/test-results.json"
        SUMMARY_ARGS = f"--test_results {RESULT_FILE} "

    canisters_path = os.path.join(CI_PROJECT_DIR, f"{ARTIFACT_DIR}/canisters")
    release_path = os.path.join(CI_PROJECT_DIR, f"{ARTIFACT_DIR}/release")
    icos_path = os.path.join(CI_PROJECT_DIR, f"{ARTIFACT_DIR}/icos")

    logging.info(f"Artifacts will be stored in: {ARTIFACT_DIR}.")

    # For an easy deletion of all artifact folders produced by the `prod-test-driver` process,
    # we create a dedicated tmp directory for this process and set TMPDIR env variable.
    test_driver_tmp_dir = tempfile.mkdtemp(prefix="tmp_test_driver_")
    # Similarly for an easy deletion of TestEnv folders/files, we create a tmp folder.
    working_tmp_dir = tempfile.mkdtemp(prefix="tmp_working_")
    folders_to_remove.extend([test_driver_tmp_dir, working_tmp_dir])

    env_dict = create_env_variables(
        is_local_run=is_local_run,
        artifact_dir=ARTIFACT_DIR,
        ci_project_dir=CI_PROJECT_DIR,
        tmp_dir=test_driver_tmp_dir,
    )

    # Print all input environmental variables.
    logging.debug(
        f"CI_PROJECT_DIR={CI_PROJECT_DIR}, TEST_ES_HOSTNAMES={TEST_ES_HOSTNAMES}, SHELL_WRAPPER={SHELL_WRAPPER}, "
        f"SSH_KEY_DIR={SSH_KEY_DIR}, IC_VERSION_ID={IC_VERSION_ID}, JOB_ID={JOB_ID}, DEV_IMG_URL={IC_OS_DEV_IMG_URL}, "
        f"DEV_IMG_SHA256={IC_OS_DEV_IMG_SHA256}, CI_PARENT_PIPELINE_SOURCE={CI_PARENT_PIPELINE_SOURCE}"
    )

    if use_locally_prebuilt_artifacts:
        logging.info(f"Extracting artifacts from the locally prebuilt {ARTIFACT_DIR} dir.")
        extract_artifacts(
            source_dir=canisters_path, dest_dir=ARTIFACT_DIR, delete_source_dir=False, is_set_executable=False
        )
        extract_artifacts(source_dir=icos_path, dest_dir=ARTIFACT_DIR, delete_source_dir=False, is_set_executable=False)
        extract_artifacts(
            source_dir=release_path, dest_dir=ARTIFACT_DIR, delete_source_dir=False, is_set_executable=True
        )
    elif is_merge_request:
        logging.info(f"Extracting artifacts from {ARTIFACT_DIR} dir.")
        extract_artifacts(
            source_dir=canisters_path, dest_dir=ARTIFACT_DIR, delete_source_dir=True, is_set_executable=False
        )
        extract_artifacts(
            source_dir=release_path, dest_dir=ARTIFACT_DIR, delete_source_dir=True, is_set_executable=True
        )
    else:
        logging.info(f"Downloading dependencies built from commit: {GREEN}{IC_VERSION_ID}{NC}")
        RCLONE_ARGS = f"--git-rev {IC_VERSION_ID} --out={ARTIFACT_DIR} --unpack --mark-executable"
        clone_artifacts_canisters_cmd = (
            f"{CI_PROJECT_DIR}/gitlab-ci/src/artifacts/rclone_download.py --remote-path=canisters {RCLONE_ARGS}"
        )
        clone_artifacts_release_cmd = (
            f"{CI_PROJECT_DIR}/gitlab-ci/src/artifacts/rclone_download.py --remote-path=release {RCLONE_ARGS}"
        )
        download_canisters_returncode = run_command(command=clone_artifacts_canisters_cmd)
        download_release_returncode = run_command(command=clone_artifacts_release_cmd)
        if download_canisters_returncode != 0:
            logging.error(f"{RED}Failed to download canisters artifacts.{NC}")
        if download_release_returncode != 0:
            logging.error(f"{RED}Failed to download release artifacts.{NC}")

    logging.debug("ARTIFACTS_DIR content:")
    os.system(f"ls -R {ARTIFACT_DIR}")

    run_test_driver_cmd = " ".join(
        [
            SHELL_WRAPPER,
            RUN_CMD,
            ADDITIONAL_ARGS,
            runner_args,
            f"--job-id={JOB_ID}",
            f"--initial-replica-version={IC_VERSION_ID}",
            f"--ic-os-img-url={IC_OS_DEV_IMG_URL}",
            f"--ic-os-img-sha256={IC_OS_DEV_IMG_SHA256}",
            f"--boundary-node-img-url={BOUNDARY_NODE_IMG_URL}",
            f"--boundary-node-img-sha256={BOUNDARY_NODE_IMG_SHA256}",
            f"--nns-canister-path={ARTIFACT_DIR}",
            f"--authorized-ssh-accounts={SSH_KEY_DIR}",
            f"--result-file={RESULT_FILE}",
            f"--journalbeat-hosts={TEST_ES_HOSTNAMES}",
            f"--working-dir={working_tmp_dir}",
        ]
    )
    testrun_returncode = run_command(command=run_test_driver_cmd, env=env_dict)

    # Both 0 and 1 (case with some failed tests) exit codes are considered to be successful executions of the test suite.
    # All other exit codes are treated as errors. For those we don't generate summary, or push messages to slack or honeycomb.
    if not (testrun_returncode == 0 or testrun_returncode == 1):
        exit_with_log(f"Execution of prod-test-driver failed unexpectedly with {testrun_returncode} exit code.")

    if is_honeycomb_push:
        logging.info("Pushing results to honeycomb.")
        honeycomb_cmd = (
            f"python3 {CI_PROJECT_DIR}/gitlab-ci/src/test_results/honeycomb.py "
            f"--test_results={RESULT_FILE} --trace_id={ROOT_PIPELINE_ID} --parent_id={JOB_ID} --type=farm-based-tests"
        )
        honeycomb_returncode = run_command(command=honeycomb_cmd)
        if honeycomb_returncode == 0:
            logging.info("Successfully pushed results to honeycomb.")
        else:
            logging.error(f"{RED}Failed to push results to honeycomb.{NC}")

    if is_slack_notify:
        msg = " ".join(
            [
                f"Pot \`{{}}\` *failed*. <{CI_JOB_URL}|log>.",  # noqa
                f"Commit: <{CI_PROJECT_URL}/-/commit/{CI_COMMIT_SHA}|{CI_COMMIT_SHORT_SHA}>.",
                f"IC_VERSION_ID: \`{IC_VERSION_ID}\`.",  # noqa
            ]
        )
        SUMMARY_ARGS += f'--slack_message "{msg}"'

    logging.debug(f"SUMMARY_ARGS={SUMMARY_ARGS}")

    # NOTE: redirect stdout to stderr, to show the output in gitlab CI.
    # This hack should be reworked by importing the script and passing the logger.
    run_summary_cmd = f"python3 {CI_PROJECT_DIR}/gitlab-ci/src/test_results/summary.py {SUMMARY_ARGS} 1>&2"
    summary_run_returncode = run_command(command=run_summary_cmd, env=env_dict)
    if summary_run_returncode == 0:
        logging.info("Summary created successfully.")
    else:
        logging.error(f"{RED}Failed to create summary.{NC}")

    return testrun_returncode


if __name__ == "__main__":
    # Check that for local runs script is launched from the nix-shell.
    is_local_run = os.getenv("CI_JOB_ID", default=None) is None
    in_nix_shell = "IN_NIX_SHELL" in os.environ
    if is_local_run and not in_nix_shell:
        exit_with_log("This script must be run from the nix-shell.")
    runner_args = " ".join(sys.argv[1:])
    logging.debug(f"Input arguments are: {runner_args}")
    if any([i in runner_args for i in ["-h", "--help"]]):
        run_help_command()
        sys.exit(0)
    keep_tmp_artifacts_folder = False
    # Check if optional flag of keeping tmp artifact folder is set.
    if "--keep_artifacts" in runner_args:
        keep_tmp_artifacts_folder = True
        # Delete the flag from the arguments, as it is not intended for `prod-test-driver`
        runner_args = runner_args.replace("--keep_artifacts", "")
    # Run main() in try/catch to delete tmp folders (marked for deletion) in case of exceptions or user interrupts.
    folders_to_remove: List[str] = []
    testrun_returncode = 1
    try:
        testrun_returncode = main(runner_args, folders_to_remove, keep_tmp_artifacts_folder)
    except Exception as e:
        logging.exception(f"Raised exception: {e}")
    finally:
        remove_folders(folders_to_remove)
        if keep_tmp_artifacts_folder:
            logging.info(f"{RED}Artifacts folder is not deleted `--keep_artifacts` was set by the user.{NC}")
    sys.exit(testrun_returncode)
