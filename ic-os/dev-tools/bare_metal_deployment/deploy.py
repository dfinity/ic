#!/usr/bin/env python3
from __future__ import annotations

import functools
import os
import re
import site
import sys
import tempfile
import time
from dataclasses import dataclass
from ipaddress import IPv6Address
from multiprocessing import Pool
from pathlib import Path
from typing import Any, List, Optional

import fabric
import invoke
import requests
import tqdm
from loguru import logger as log
from simple_parsing import field, parse
from simple_parsing.helpers import flag

DEFAULT_IDRAC_SCRIPT_DIR = f"{site.getuserbase()}/bin"

# IDRAC versions after 6 use different REST API endpoints.
NEWER_IDRAC_VERSION_THRESHOLD = 6000000

DEFAULT_SETUPOS_WAIT_TIME_MINS = 20

BMC_INFO_ENV_VAR = "BMC_INFO_CSV_FILENAME"

DISABLE_PROGRESS_BAR = True


@dataclass
class Args:
    """
    Deploy an image to a set of servers given their BMC IP's and login info's. Works via iDRAC only (currently).
    Requires NFS file share local to the server which will be deployed.
    Use --config_path <yaml file> to load args from a file. Args on the command line will override config file args.
    """

    # Endpoint for NFS enabled fileshare, e.g. zh2-rmu or 10.10.101.254
    file_share_url: str = field(alias="-u")

    # Directory on the remote file share where files are served from. E.g. /srv/images. This will be postfixed to the file_share_url, e.g.: 10.10.101.254:/srv/images
    file_share_dir: str = field(alias="-d")

    # SetupOS image filename on the remote file share to be mounted. Must have extension '.img'. E.g. setupos.img.
    file_share_image_filename: str = field(alias="-i")

    csv_filename: Optional[str] = field(alias="-c")
    """
    CSV file with each row containing 'bmc_ip_address,bmc_username,bmc_password[,guestos_ipv6_address]'. If not supplied, the environment variable "BMC_INFO_CSV_FILENAME" will be checked. If neither are found, error. If guestos_ipv6_address is present, the guestos endpoint will be checked for connectivity to determine deployment success. Otherwise deployment will be considered successful after the timeout.
    """

    # Username for SSH/SCP access to file share. Defaults to the current username
    file_share_username: Optional[str] = None

    # SSH private key file for access to file share. This is passed via the '-i' flag to `scp`. If omitted, the '-i' flag is omitted.
    file_share_ssh_key: Optional[str] = None

    upload_img: Optional[str] = field(default=None, alias="-f")
    """
    If specified, file will be scp'd to `file_share_url`, decompressed, and the contained disk.img file moved to `file_share_dir` and renamed to `file_share_image_filename`.
    Assumptions:
      File is a zstd compressed tar archive.
      Tar archive contains a single file - disk.img
      SSH certificate access to the file share
      Write access to `file_share_dir` on the remote file share
    """

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_node_reward_type: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_ipv6_prefix: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_ipv6_gateway: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_ipv4_address: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_ipv4_gateway: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_ipv4_prefix_length: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_domain: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_image_verbose: Optional[str] = None

    # If present - decompress `upload_img` and inject this into config.ini
    inject_enable_trusted_execution_environment: Optional[str] = None

    # If present - decompress `upload_img` and inject this into ssh_authorized_keys/admin
    inject_image_pub_key: Optional[str] = None

    # Path to the setupos-inject-config tool. Necessary if any inject* args are present
    inject_configuration_tool: Optional[str] = None

    # Time to wait between each remote deployment, in minutes
    wait_time: int = field(default=DEFAULT_SETUPOS_WAIT_TIME_MINS, alias="-t")

    # How many nodes should be deployed in parallel
    parallel: int = 1

    # Path to an idrac script, which we use to find the directory. If None, pip bin directory will be used.
    idrac_script: Optional[str] = None

    # Disable progress bars if True
    ci_mode: bool = flag(default=False)

    # Run benchmarks if True
    benchmark: bool = flag(default=False)

    # Run HostOS metrics check if True
    check_hostos_metrics: bool = flag(default=False)

    # Check HSM capability if True
    hsm: bool = flag(default=False)

    # Path to the benchmark_driver script.
    benchmark_driver_script: Optional[str] = "./benchmark_driver.sh"

    # Path to the benchmark_runner script.
    benchmark_runner_script: Optional[str] = "./benchmark_runner.sh"

    # Paths to any benchmark tool scripts.
    benchmark_tools: Optional[List[str]] = field(
        default_factory=lambda: ["../hw_validation/stress.sh", "../hw_validation/benchmark.sh"]
    )

    def __post_init__(self):
        assert self.upload_img is None or self.upload_img.endswith(
            ".tar.zst"
        ), "`upload_img` must be a zstd compressed tar file. Use the build artifact."

        csv_filename_env_var = os.environ.get(BMC_INFO_ENV_VAR)
        assert (
            csv_filename_env_var or self.csv_filename
        ), f"csv file must be specified via CLI or environment variable {BMC_INFO_ENV_VAR}"
        self.csv_filename = self.csv_filename or csv_filename_env_var

        assert (self.inject_image_ipv6_prefix and self.inject_image_ipv6_gateway) or not (
            self.inject_image_ipv6_prefix or self.inject_image_ipv6_gateway
        ), "Both ipv6_prefix and ipv6_gateway flags must be present or none"
        if self.inject_image_ipv6_prefix:
            assert self.inject_configuration_tool, "setupos_inject_config tool required to modify image"
        ipv4_args = [
            self.inject_image_ipv4_address,
            self.inject_image_ipv4_gateway,
            self.inject_image_ipv4_prefix_length,
            self.inject_image_domain,
        ]
        assert all(ipv4_args) or not any(ipv4_args), "All ipv4 flags must be present or none"
        assert (
            self.file_share_ssh_key is None or Path(self.file_share_ssh_key).exists()
        ), "File share ssh key path does not exist"


@dataclass(frozen=True)
class BMCInfo:
    ip_address: str
    username: str
    password: str
    network_image_url: str
    guestos_ipv6_address: IPv6Address
    hostos_ipv6_address: IPv6Address

    def __post_init__(self):
        def assert_not_empty(name: str, x: Any) -> None:
            assert x, f"{name} cannot be empty. Got: {x}"

        assert_not_empty("Username", self.username)
        assert_not_empty("Password", self.password)
        assert_not_empty("Network image url", self.network_image_url)

    # Don't print secrets
    def __str__(self):
        return f"BMCInfo(ip_address={self.ip_address}, username={self.username}, password=<redacted>, network_image_url={self.network_image_url}, hostos_ipv6_address={self.hostos_ipv6_address}, guestos_ipv6_address={self.guestos_ipv6_address})"

    def __repr__(self):
        return self.__str__()

    def __format__(self, format_spec):
        return self.__str__()


@dataclass(frozen=True)
class OperationResult:
    bmc_info: BMCInfo
    success: bool
    error_msg: Optional[str] = None


@dataclass(frozen=True)
class Ipv4Args:
    address: str
    gateway: str
    prefix_length: str
    domain: str


def parse_from_row(row: List[str], network_image_url: str) -> BMCInfo:
    if len(row) == 4:
        ip_address, username, password, guestos_ipv6_address = row
        hostos_ipv6_address = guestos_ipv6_address.replace("6801", "6800", 1)

        return BMCInfo(
            ip_address,
            username,
            password,
            network_image_url,
            IPv6Address(guestos_ipv6_address),
            IPv6Address(hostos_ipv6_address),
        )

    assert False, f"Invalid csv row found. Must be 4 items: {row}"


def parse_from_csv_file(csv_filename: str, network_image_url: str) -> List["BMCInfo"]:
    with open(csv_filename, "r") as csv_file:
        rows = [line.strip().split(",") for line in csv_file]
        return [parse_from_row(row, network_image_url) for row in rows]


def assert_ssh_connectivity(target_url: str, ssh_key_file: Optional[Path]):
    ssh_key_arg = f"-i {ssh_key_file}" if ssh_key_file else ""
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    result = invoke.run(f"ssh {ssh_opts} {ssh_key_arg} {target_url} 'echo Testing connection'", warn=True)
    assert result and result.ok, f"SSH connection test failed: {result.stderr.strip()}"


def get_url_content(url: str, timeout_secs: int = 1) -> Optional[str]:
    try:
        response = requests.get(url, verify=False, timeout=timeout_secs)
        if not response.ok:
            log.warning(f"Response from {url}: {response.status_code} - {response.reason}")
            return None
        return response.text
    except requests.Timeout:
        log.warning(f"Timed out while connecting to {url}")
        return None


def check_hostos_power_metrics(metrics_output: str) -> bool:
    try:
        power_metric_line = next(
            line
            for line in metrics_output.splitlines()
            if not line.startswith("#") and re.fullmatch(r"power_average_watts \d+", line)
        )
        log.info(f"power consumption metric: {power_metric_line}")
        return True
    except StopIteration:
        log.warning("power_average_watts metric in HostOS metrics not found or invalid")
        return False


def check_hostos_version_metrics(metrics_output: str) -> bool:
    for metric in ["hostos_version", "hostos_config_version"]:
        try:
            pattern_template = rf"{re.escape(metric)}\{{version=\".*\"\}} 1"
            version_metric_line = next(
                line
                for line in metrics_output.splitlines()
                if not line.startswith("#") and re.fullmatch(pattern_template, line)
            )
            log.info(f"{metric} metric: {version_metric_line}")
        except StopIteration:
            log.warning(f"{metric} metric in HostOS metrics not found or invalid")
            return False
    return True


def check_hostos_hw_generation_metrics(metrics_output: str) -> bool:
    try:
        expected_line = 'node_hardware_generation{gen="Gen2"} 1'
        version_metric_line = next(
            line for line in metrics_output.splitlines() if not line.startswith("#") and line == expected_line
        )
        log.info(f"node_hardware_generation metric: {version_metric_line}")
        return True
    except StopIteration:
        log.warning("node_hardware_generation metric in HostOS metrics not found or invalid")
        return False


def check_guestos_ping_connectivity(ip_address: IPv6Address, timeout_secs: int) -> bool:
    # Ping target with count of 1, STRICT timeout of `timeout_secs`.
    # This will break if latency is > `timeout_secs`.
    result = invoke.run(f"ping6 -c1 -w{timeout_secs} {ip_address}", warn=True, hide=True)
    if not result or not result.ok:
        return False

    log.info("Ping success.")
    return True


def check_guestos_metrics_version(ip_address: IPv6Address, timeout_secs: int) -> bool:
    metrics_endpoint = f"https://[{ip_address.exploded}]:9100/metrics"
    log.info(f"Attempting GET on metrics at {metrics_endpoint}...")
    metrics_output = get_url_content(metrics_endpoint, timeout_secs)
    if not metrics_output:
        log.warning(f"Request to {metrics_endpoint} failed.")
        return False

    log.info("Got metrics result from GuestOS")
    try:
        guestos_version_line = next(
            line for line in metrics_output.splitlines() if not line.startswith("#") and "guestos_version{" in line
        )
        log.info(f"GuestOS version metric: {guestos_version_line}")
        return True
    except StopIteration:
        log.warning("guestos_version metric not found in GuestOS metrics")
        return False


def check_guestos_hsm_capability(ip_address: IPv6Address, ssh_key_file: Optional[str] = None) -> bool:
    # Check that the HSM is working correctly, over an SSH session with the node.
    log.info(f"Starting HSM capability check for {ip_address}")

    ssh_key_arg = f"-i {ssh_key_file}" if ssh_key_file else ""
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    # Execute the HSM command
    log.info(f"Executing HSM command on {ip_address}")
    hsm_command = "/opt/ic/bin/vsock_guest --attach-hsm && sleep 5 && pkcs11-tool --list-slots | grep 'Nitrokey HSM'"
    result = invoke.run(
        f'ssh {ssh_opts} {ssh_key_arg} admin@{ip_address} "{hsm_command}"',
        warn=True,
    )

    if not result or not result.ok:
        log.error(f"HSM command failed on {ip_address}")
        if result:
            log.error(f"HSM command stderr: {result.stderr.strip()}")
            log.error(f"HSM command stdout: {result.stdout.strip()}")
            # Check if it's an SSH connectivity issue vs HSM-specific issue
            if result.returncode == 255 or "Connection refused" in result.stderr or "No route to host" in result.stderr:
                log.error(f"SSH connectivity issue detected for {ip_address}")
            else:
                log.error(f"HSM-specific issue detected for {ip_address}")
        return False

    log.info(f"HSM command executed successfully on {ip_address}")
    log.info("HSM check success.")
    return True


def wait(wait_secs: int) -> bool:
    time.sleep(wait_secs)
    return False


def check_idrac_version(bmc_info: BMCInfo):
    response = requests.get(
        f"https://{bmc_info.ip_address}/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion",
        verify=False,
        auth=(bmc_info.username, bmc_info.password),
    )
    data = response.json()
    assert response.status_code == 200, "ERROR - Cannot get idrac version"
    idrac_version = int(data["FirmwareVersion"].replace(".", ""))
    assert idrac_version >= 6000000, "ERROR - Old idrac version detected. Please update idrac version to >= 6"
    # todo - return or raise an error.


@dataclass
class DeploymentError(Exception):
    result: OperationResult


def gen_failure(result: invoke.Result, bmc_info: BMCInfo) -> DeploymentError:
    error_msg = f"Failure: {result.stderr}"
    return DeploymentError(OperationResult(bmc_info, success=False, error_msg=error_msg))


def run_script(idrac_script_dir: Path, bmc_info: BMCInfo, script_and_args: str, permissive: bool = True) -> None:
    """Run a given script from the given bin dir and raise an exception if anything went wrong"""
    command = f"python3 {idrac_script_dir}/{script_and_args}"
    result = invoke.run(command)

    if result and not result.ok:
        raise gen_failure(result, bmc_info)

    if not permissive and result and "FAIL" in result.stdout:
        raise gen_failure(result, bmc_info)


def configure_process_local_log(server_id: str):
    """
    Assumes currently running in a separate process
    Modifies the global log to include `server_id`
    Should not affect the main thread
    """
    logger_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "Server - {extra[server_id]} - <level>{message}</level>"
    )
    log.configure(extra={"server_id": server_id})
    log.remove()
    log.add(sys.stderr, format=logger_format)


def deploy_server(
    bmc_info: BMCInfo,
    wait_time_mins: int,
    idrac_script_dir: Path,
    file_share_ssh_key: Optional[str] = None,
    check_hsm: bool = False,
):
    # Partially applied function for brevity
    run_func = functools.partial(run_script, idrac_script_dir, bmc_info)

    check_idrac_version(bmc_info)

    configure_process_local_log(f"{bmc_info.ip_address}")
    cli_creds = f"-ip {bmc_info.ip_address} -u {bmc_info.username} -p {bmc_info.password}"

    # Keep state of if we attached the image
    network_image_attached = False
    try:
        log.info("*** Starting deployment...")

        # Get a reference point
        log.info("Turning off machine")
        run_func(
            f"GetSetPowerStateREDFISH.py {cli_creds} -p {bmc_info.password} --set ForceOff",
        )
        for i in tqdm.tqdm(range(int(60)), disable=DISABLE_PROGRESS_BAR):
            time.sleep(1)

        log.info(
            "Ejecting all virtual media from the machine. iDRAC only supports one type of media at a time (floppy vs CD). May display error if no virtual media attached"
        )
        run_func(
            f"InsertEjectVirtualMediaREDFISH.py {cli_creds} --action eject --index 1",
        )
        run_func(
            f"InsertEjectVirtualMediaREDFISH.py {cli_creds} --action eject --index 2",
        )
        log.info("Attaching virtual media")
        run_func(
            f"InsertEjectVirtualMediaREDFISH.py {cli_creds} --uripath {bmc_info.network_image_url} --action insert --index 1",
            permissive=False,
        )
        network_image_attached = True

        log.info("Setting next boot device to virtual floppy, and restarting")
        run_func(
            f"SetNextOneTimeBootVirtualMediaDeviceOemREDFISH.py {cli_creds} --device 2",
            permissive=False,
        )  # Device 2 for virtual Floppy

        log.info("Turning on machine")
        run_func(
            f"GetSetPowerStateREDFISH.py {cli_creds} -p {bmc_info.password} --set On",
        )

        timeout_secs = 5

        def check_connectivity_func() -> bool:
            log.info(f"Checking guestos ({bmc_info.guestos_ipv6_address}) connectivity...")

            result = check_guestos_ping_connectivity(bmc_info.guestos_ipv6_address, timeout_secs)
            result = result and check_guestos_metrics_version(bmc_info.guestos_ipv6_address, timeout_secs)

            if check_hsm:
                result = result and check_guestos_hsm_capability(bmc_info.guestos_ipv6_address, file_share_ssh_key)

            return result

        log.info(f"Machine booting. Checking on SetupOS completion periodically. Timeout (mins): {wait_time_mins}")
        start_time = time.time()
        end_time = start_time + wait_time_mins * 60
        while time.time() < end_time:
            if check_connectivity_func():
                log.info("*** Deployment SUCCESS!")
                return OperationResult(bmc_info, success=True)
            time.sleep(timeout_secs)
        raise Exception("Could not successfully verify connectivity to node.")

    except DeploymentError as e:
        log.error(f"Error: {e.result.error_msg}")
        log.error("*** Deployment FAILED!")
        return e.result

    except Exception as e:
        log.error(f"Unknown error occurred: {e}")
        log.error("Deployment FAILED!")
        return OperationResult(bmc_info, success=False, error_msg=f"{e}")

    finally:
        if network_image_attached:
            try:
                log.info("Ejecting the attached image so the next machine can boot from it")
                run_func(
                    f"InsertEjectVirtualMediaREDFISH.py {cli_creds} --action eject --index 1",
                )
                network_image_attached = False
            except Exception as e:
                return e.args[0]


def boot_images(
    bmc_infos: List[BMCInfo],
    parallelism: int,
    wait_time_mins: int,
    idrac_script_dir: Path,
    file_share_ssh_key: Optional[str] = None,
    check_hsm: bool = False,
):
    results: List[OperationResult] = []

    arg_tuples = ((bmc_info, wait_time_mins, idrac_script_dir, file_share_ssh_key, check_hsm) for bmc_info in bmc_infos)

    with Pool(parallelism) as p:
        results = p.starmap(deploy_server, arg_tuples)

    log.info("Deployment summary:")
    deployment_failure = False
    for res in results:
        log.info(res)
        if not res.success:
            deployment_failure = True

    if deployment_failure:
        log.error("One or more node deployments failed")
        return False
    else:
        log.info("All deployments completed successfully.")
        return True


def benchmark_node(
    bmc_info: BMCInfo,
    benchmark_driver_script: str,
    benchmark_runner_script: str,
    benchmark_tools: List[str],
    file_share_ssh_key: Optional[str] = None,
):
    log.info("Benchmarking machine.")

    ip_address = bmc_info.guestos_ipv6_address

    benchmark_tools = " ".join(benchmark_tools) if benchmark_tools is not None else ""

    # Throw away the result, for now
    invoke.run(
        f"{benchmark_driver_script} {benchmark_runner_script} {file_share_ssh_key} {ip_address} {benchmark_tools}",
        warn=True,
    )
    return OperationResult(bmc_info, success=True)


def benchmark_nodes(
    bmc_infos: List[BMCInfo],
    parallelism: int,
    benchmark_driver_script: str,
    benchmark_runner_script: str,
    benchmark_tools: List[str],
    file_share_ssh_key: Optional[str] = None,
):
    results: List[OperationResult] = []

    arg_tuples = (
        (bmc_info, benchmark_driver_script, benchmark_runner_script, benchmark_tools, file_share_ssh_key)
        for bmc_info in bmc_infos
    )

    with Pool(parallelism) as p:
        results = p.starmap(benchmark_node, arg_tuples)

    log.info("Benchmark summary:")
    benchmark_failure = False
    for res in results:
        log.info(res)
        if not res.success:
            benchmark_failure = True

    if benchmark_failure:
        log.error("One or more node benchmarks failed")
        return False
    else:
        log.info("All benchmarks completed successfully.")
        return True


def check_node_hostos_metrics(bmc_info: BMCInfo):
    log.info("Checking HostOS metrics.")

    metrics_endpoint = f"https://[{bmc_info.hostos_ipv6_address.exploded}]:9100/metrics"
    log.info(f"Attempting GET on metrics at {metrics_endpoint}...")
    metrics_output = get_url_content(metrics_endpoint, 5)
    if not metrics_output:
        log.warning(f"Request to {metrics_endpoint} failed.")
        return OperationResult(bmc_info, success=False)

    result = (
        check_hostos_power_metrics(metrics_output)
        and check_hostos_version_metrics(metrics_output)
        and check_hostos_hw_generation_metrics(metrics_output)
    )

    return OperationResult(bmc_info, success=result)


def check_nodes_hostos_metrics(
    bmc_infos: List[BMCInfo],
    parallelism: int,
):
    results: List[OperationResult] = []

    with Pool(parallelism) as p:
        results = p.map(check_node_hostos_metrics, bmc_infos)

    log.info("HostOS metrics check summary:")
    metrics_check_failure = False
    for res in results:
        log.info(res)
        if not res.success:
            metrics_check_failure = True

    if metrics_check_failure:
        log.error("The metrics check failed on one or more nodes.")
        return False
    else:
        log.info("All nodes correctly export the hostOS metrics.")
        return True


def create_file_share_endpoint(file_share_url: str, file_share_username: Optional[str]) -> str:
    return file_share_url if file_share_username is None else f"{file_share_username}@{file_share_url}"


def upload_to_file_share(
    upload_img: Path,
    file_share_endpoint: str,
    file_share_dir: str,
    file_share_image_name: str,
    file_share_ssh_key: Optional[str] = None,
):
    log.info(f'''Uploading "{upload_img}" to "{file_share_endpoint}"''')

    connect_kw_args = {"key_filename": file_share_ssh_key} if file_share_ssh_key else None
    conn = fabric.Connection(host=file_share_endpoint, connect_kwargs=connect_kw_args)
    tmp_dir = None
    try:
        result = conn.run("mktemp --directory", hide="both", echo=True)
        tmp_dir = str.strip(result.stdout)
        # scp is faster than fabric's built-in transfer.
        ssh_key_arg = f"-i {file_share_ssh_key}" if file_share_ssh_key else ""
        invoke.run(
            f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_key_arg} {upload_img}  {file_share_endpoint}:{tmp_dir}",
            echo=True,
            pty=True,
        )

        upload_img_filename = upload_img.name
        # Decompress in place. disk.img should appear in the same directory
        conn.run(f"tar --extract --zstd --file {tmp_dir}/{upload_img_filename} --directory {tmp_dir}", echo=True)
        image_destination = f"/{file_share_dir}/{file_share_image_name}"
        conn.run(f"mv {tmp_dir}/disk.img {image_destination}", echo=True)
        conn.run(f"chmod a+r {image_destination}", echo=True)
    finally:
        # Clean up remote dir
        if tmp_dir:
            conn.run(f"rm --force --recursive {tmp_dir}", echo=True)

    log.info(f"Image ready at {file_share_endpoint}:/{file_share_dir}/{file_share_image_name}")


def inject_config_into_image(
    setupos_inject_config_path: Path,
    working_dir: Path,
    compressed_image_path: Path,
    node_reward_type: str,
    ipv6_prefix: str,
    ipv6_gateway: str,
    inject_enable_trusted_execution_environment: Optional[str],
    ipv4_args: Optional[Ipv4Args],
    verbose: Optional[str],
    pub_key: Optional[str],
) -> Path:
    """
    Transform the compressed image.
    * Decompress image into working_dir
    * Inject config
    * Recompress
    Does not remove any files or dirs.
    Returns path to compressed new image.
    """
    assert working_dir.is_dir()
    assert compressed_image_path.exists()

    def is_executable(p: Path) -> bool:
        return os.access(p, os.X_OK)

    assert setupos_inject_config_path.exists() and is_executable(setupos_inject_config_path)

    invoke.run(f"tar --extract --zstd --file {compressed_image_path} --directory {working_dir}", echo=True)

    img_path = Path(f"{working_dir}/disk.img")
    assert img_path.exists()

    image_part = f"--image-path {img_path}"
    reward_part = f"--node-reward-type {node_reward_type}"
    prefix_part = f"--ipv6-prefix {ipv6_prefix} "
    prefix_part += "--ipv6-prefix-length 64"
    gateway_part = f"--ipv6-gateway {ipv6_gateway}"
    ipv4_part = ""
    if ipv4_args:
        ipv4_part = f"--ipv4-address {ipv4_args.address} "
        ipv4_part += f"--ipv4-gateway {ipv4_args.gateway} "
        ipv4_part += f"--ipv4-prefix-length {ipv4_args.prefix_length} "
        ipv4_part += f"--domain-name {ipv4_args.domain} "

    enable_trusted_execution_environment_part = ""
    if inject_enable_trusted_execution_environment is not None:
        enable_trusted_execution_environment_part += (
            f"--enable-trusted-execution-environment {inject_enable_trusted_execution_environment}"
        )

    verbose_part = ""
    if verbose:
        verbose_part = f"--verbose {verbose} "

    admin_key_part = ""
    if pub_key:
        admin_key_part = f'--public-keys "{pub_key}"'

    invoke.run(
        f"{setupos_inject_config_path} {image_part} {reward_part} {prefix_part} {gateway_part} {ipv4_part} {enable_trusted_execution_environment_part} {verbose_part} {admin_key_part}",
        echo=True,
    )

    # Reuse the name of the compressed image path in the working directory
    result_filename = compressed_image_path.name
    result_path = Path(f"{working_dir}/{result_filename}")
    invoke.run(f"tar --create --zstd --file {result_path} --directory {working_dir} {img_path.name}", echo=True)

    return result_path


def main():
    print(sys.argv)
    args: Args = parse(Args, add_config_path_arg=True)  # Parse from config file too

    DISABLE_PROGRESS_BAR = args.ci_mode  # noqa - ruff format wants to erroneously delete this

    network_image_url: str = f"http://{args.file_share_url}/{args.file_share_image_filename}"
    log.info(f"Using network_image_url: {network_image_url}")

    idrac_script_dir = Path(args.idrac_script).parent if args.idrac_script else Path(DEFAULT_IDRAC_SCRIPT_DIR)
    log.info(f"Using idrac script dir: {idrac_script_dir}")

    csv_filename: str = args.csv_filename
    bmc_infos = parse_from_csv_file(csv_filename, network_image_url)

    ipv4_args = None
    if args.inject_image_ipv4_address:
        ipv4_args = Ipv4Args(
            args.inject_image_ipv4_address,
            args.inject_image_ipv4_gateway,
            args.inject_image_ipv4_prefix_length,
            args.inject_image_domain,
        )

    if args.benchmark and args.check_hostos_metrics:
        log.error("Cannot run both benchmark and check_hostos_metrics at the same time. Please choose one.")
        sys.exit(1)

    # Benchmark the nodes (no deployment)
    if args.benchmark:
        success = benchmark_nodes(
            bmc_infos=bmc_infos,
            parallelism=args.parallel,
            benchmark_driver_script=args.benchmark_driver_script,
            benchmark_runner_script=args.benchmark_runner_script,
            benchmark_tools=args.benchmark_tools,
            file_share_ssh_key=args.file_share_ssh_key,
        )

        if not success:
            sys.exit(1)

        sys.exit(0)

    # Check that all important hostos metrics are available (no deployment)
    if args.check_hostos_metrics:
        success = check_nodes_hostos_metrics(
            bmc_infos=bmc_infos,
            parallelism=args.parallel,
        )

        if not success:
            sys.exit(1)

        sys.exit(0)

    if args.upload_img or args.inject_image_ipv6_prefix:
        file_share_endpoint = create_file_share_endpoint(args.file_share_url, args.file_share_username)
        assert_ssh_connectivity(file_share_endpoint, args.file_share_ssh_key)

        if args.inject_image_ipv6_prefix:
            tmpdir = tempfile.mkdtemp()
            modified_image_path = inject_config_into_image(
                Path(args.inject_configuration_tool),
                Path(tmpdir),
                Path(args.upload_img),
                args.inject_image_node_reward_type,
                args.inject_image_ipv6_prefix,
                args.inject_image_ipv6_gateway,
                args.inject_enable_trusted_execution_environment,
                ipv4_args,
                args.inject_image_verbose,
                args.inject_image_pub_key,
            )

            upload_to_file_share(
                modified_image_path,
                file_share_endpoint,
                args.file_share_dir,
                args.file_share_image_filename,
                args.file_share_ssh_key,
            )

        elif args.upload_img:
            upload_to_file_share(
                args.upload_img,
                file_share_endpoint,
                args.file_share_dir,
                args.file_share_image_filename,
                args.file_share_ssh_key,
            )

    wait_time_mins = args.wait_time
    parallelism = args.parallel
    success = boot_images(
        bmc_infos=bmc_infos,
        parallelism=parallelism,
        wait_time_mins=wait_time_mins,
        idrac_script_dir=idrac_script_dir,
        file_share_ssh_key=args.file_share_ssh_key,
        check_hsm=args.hsm,
    )

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
