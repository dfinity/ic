#!/usr/bin/env python3
from __future__ import annotations

import functools
import os
import site
import sys
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

# May vary depending on network or other conditions!
DEFAULT_SETUPOS_WAIT_TIME_MINS = 25

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

    # Path to the setupos-inject-configuration tool. Necessary if any inject* args are present
    inject_configuration_tool: Optional[str] = None

    # Time to wait between each remote deployment, in minutes
    wait_time: int = field(default=DEFAULT_SETUPOS_WAIT_TIME_MINS, alias="-t")

    # How many nodes should be deployed in parallel
    parallel: int = 1

    # Directory where idrac scripts are held. If None, pip bin directory will be used.
    idrac_script_dir_file: Optional[str] = None

    # Disable progress bars if True
    ci_mode: bool = flag(default=False)

    def __post_init__(self):
        assert self.upload_img is None or self.upload_img.endswith(
            ".tar.zst"
        ), "`upload_img` must be a zstd compressed tar file. Use the build artifact."

        csv_filename_env_var = os.environ.get(BMC_INFO_ENV_VAR)
        assert (
            csv_filename_env_var or self.csv_filename
        ), f"csv file must be specified via CLI or environment variable {BMC_INFO_ENV_VAR}"
        self.csv_filename = self.csv_filename or csv_filename_env_var

        assert (self.inject_image_ipv6_prefix and self.inject_image_ipv6_gateway) or \
            not (self.inject_image_ipv6_prefix and self.inject_image_ipv6_gateway), \
            "Both ipv6_prefix and ipv6_gateway flags must be present or none"
        if self.inject_image_ipv6_prefix:
            assert self.inject_configuration_tool, \
                "setupos_inject_configuration tool required to modify image"
        ipv4_args = [self.inject_image_ipv4_address,
                     self.inject_image_ipv4_gateway,
                     self.inject_image_ipv4_prefix_length,
                     self.inject_image_domain]
        assert all(ipv4_args) or not any(ipv4_args), \
            "All ipv4 flags must be present or none"
        assert self.file_share_ssh_key is None \
            or Path(self.file_share_ssh_key).exists(), \
            "File share ssh key path does not exist"


@dataclass(frozen=True)
class BMCInfo:
    ip_address: str
    username: str
    password: str
    network_image_url: str
    guestos_ipv6_address: Optional[IPv6Address] = None

    def __post_init__(self):
        def assert_not_empty(name: str, x: Any) -> None:
            assert x, f"{name} cannot be empty. Got: {x}"

        assert_not_empty("Username", self.username)
        assert_not_empty("Password", self.password)
        assert_not_empty("Network image url", self.network_image_url)

    # Don't print secrets
    def __str__(self):
        return f"BMCInfo(ip_address={self.ip_address}, username={self.username}, password=<redacted>, network_image_url={self.network_image_url}, guestos_ipv6_address={self.guestos_ipv6_address})"

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
    if len(row) == 3:
        ip_address, username, password = row
        return BMCInfo(ip_address, username, password, network_image_url)

    if len(row) == 4:
        ip_address, username, password, guestos_ipv6_address = row
        return BMCInfo(
            ip_address,
            username,
            password,
            network_image_url,
            IPv6Address(guestos_ipv6_address),
        )

    assert False, f"Invalid csv row found. Must be 3 or 4 items: {row}"


def parse_from_rows(rows: List[List[str]], network_image_url: str) -> List["BMCInfo"]:
    return [parse_from_row(row, network_image_url) for row in rows]


def parse_from_csv_file(csv_filename: str, network_image_url: str) -> List["BMCInfo"]:
    with open(csv_filename, "r") as csv_file:
        rows = [line.strip().split(',') for line in csv_file]
        return [parse_from_row(row, network_image_url) for row in rows]


def assert_ssh_connectivity(target_url: str, ssh_key_file: Optional[Path]):
    ssh_key_arg = f"-i {ssh_key_file}" if ssh_key_file else ""
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    result = invoke.run(f"ssh {ssh_opts} {ssh_key_arg} {target_url} 'echo Testing connection'", warn=True)
    assert result and result.ok, \
        f"SSH connection test failed: {result.stderr.strip()}"


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
    guestos_version_line = next(
        line
        for line in metrics_output.splitlines()
        if not line.startswith("#") and "guestos_version{" in line
    )
    log.info(f"GuestOS version metric: {guestos_version_line}")
    return True


def wait(wait_secs: int) -> bool:
    time.sleep(wait_secs)
    return False


def check_idrac_version(bmc_info: BMCInfo):
    response = requests.get(f"https://{bmc_info.ip_address}/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion",
                 verify=False,
                 auth=(bmc_info.username,bmc_info.password))
    data = response.json()
    assert response.status_code == 200, "ERROR - Cannot get idrac version"
    idrac_version = int(data["FirmwareVersion"].replace('.',''))
    assert idrac_version >= 6000000, "ERROR - Old idrac version detected. Please update idrac version to >= 6"
    # todo - return or raise an error.


@dataclass
class DeploymentError(Exception):
    result: OperationResult


def gen_failure(result: invoke.Result, bmc_info: BMCInfo) -> DeploymentError:
    error_msg = f"Failed on {result.command}: {result.stderr}"
    return DeploymentError(
        OperationResult(bmc_info, success=False, error_msg=error_msg)
    )


def run_script(idrac_script_dir: Path,
               bmc_info: BMCInfo,
               script_and_args: str,
               quiet: bool = False) -> None:
    """Run a given script from the given bin dir and raise an exception if anything went wrong"""
    command = f"python3 {idrac_script_dir}/{script_and_args}"
    result = invoke.run(command, hide="stdout" if quiet else None)
    if result and not result.ok:
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


def deploy_server(bmc_info: BMCInfo, wait_time_mins: int, idrac_script_dir: Path):
    # Partially applied function for brevity
    run_func = functools.partial(run_script, idrac_script_dir, bmc_info)

    check_idrac_version(bmc_info)

    configure_process_local_log(f"{bmc_info.ip_address}")
    cli_creds = (
        f"-ip {bmc_info.ip_address} -u {bmc_info.username} -p {bmc_info.password}"
    )

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
        )
        network_image_attached = True

        log.info("Setting next boot device to virtual floppy, and restarting")
        run_func(
            f"SetNextOneTimeBootVirtualMediaDeviceOemREDFISH.py {cli_creds} --device 2"
        ) # Device 2 for virtual Floppy

        log.info("Turning on machine")
        run_func(
            f"GetSetPowerStateREDFISH.py {cli_creds} -p {bmc_info.password} --set On",
        )

        # If guestos ipv6 address is present, loop on checking connectivity.
        # Otherwise, just wait.
        timeout_secs = 5

        def wait_func() -> bool:
            wait(timeout_secs)
            return False

        def check_connectivity_func() -> bool:
            assert bmc_info.guestos_ipv6_address is not None, "Logic error"
            return check_guestos_ping_connectivity(
                bmc_info.guestos_ipv6_address, timeout_secs
            ) and check_guestos_metrics_version(
                bmc_info.guestos_ipv6_address, timeout_secs
            )

        iterate_func = (
            check_connectivity_func if bmc_info.guestos_ipv6_address else wait_func
        )

        log.info(
            f"Machine booting. Checking on SetupOS completion periodically. Timeout (mins): {wait_time_mins}"
        )
        for i in tqdm.tqdm(range(int(60 * (wait_time_mins / timeout_secs))),disable=DISABLE_PROGRESS_BAR):
            if iterate_func():
                log.info("*** Deployment SUCCESS!")
                return OperationResult(bmc_info, success=True)

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
                log.info(
                    "Ejecting the attached image so the next machine can boot from it"
                )
                run_func(
                    f"InsertEjectVirtualMediaREDFISH.py {cli_creds} --action eject --index 1",
                )
                network_image_attached = False
            except Exception as e:
                return e.args[0]


def boot_images(bmc_infos: List[BMCInfo],
                parallelism: int,
                wait_time_mins: int,
                idrac_script_dir: Path):
    results: List[OperationResult] = []

    arg_tuples = ((bmc_info, wait_time_mins, idrac_script_dir) \
                  for bmc_info in bmc_infos)

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


def create_file_share_endpoint(file_share_url: str,
                               file_share_username: Optional[str]) -> str:
    return file_share_url \
        if file_share_username is None \
        else f"{file_share_username}@{file_share_url}"


def upload_to_file_share(
    upload_img: Path,
    file_share_endpoint: str,
    file_share_dir: str,
    file_share_image_name: str,
    file_share_ssh_key: Optional[str] = None,
):
    log.info(f'''Uploading "{upload_img}" to "{file_share_endpoint}"''')

    connect_kw_args = {"key_filename": file_share_ssh_key} if file_share_ssh_key else None
    conn = fabric.Connection(host=file_share_endpoint,
                             connect_kwargs=connect_kw_args)
    tmp_dir = None
    try:
        result = conn.run("mktemp --directory", hide="both", echo=True)
        tmp_dir = str.strip(result.stdout)
        # scp is faster than fabric's built-in transfer.
        ssh_key_arg = f"-i {file_share_ssh_key}" if file_share_ssh_key else ""
        invoke.run(f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_key_arg} {upload_img}  {file_share_endpoint}:{tmp_dir}", echo=True, pty=True)

        upload_img_filename = upload_img.name
        # Decompress in place. disk.img should appear in the same directory
        conn.run(f"tar --extract --zstd --file {tmp_dir}/{upload_img_filename} --directory {tmp_dir}", echo=True)
        image_destination = f"/{file_share_dir}/{file_share_image_name}"
        conn.run(
            f"mv {tmp_dir}/disk.img {image_destination}",
            echo=True
        )
        conn.run(f"chmod a+r {image_destination}", echo=True)
    finally:
        # Clean up remote dir
        if tmp_dir:
            conn.run(f"rm --force --recursive {tmp_dir}", echo=True)

    log.info(f"Image ready at {file_share_endpoint}:/{file_share_dir}/{file_share_image_name}")


def inject_config_into_image(setupos_inject_configuration_path: Path,
                             working_dir: Path,
                             compressed_image_path: Path,
                             ipv6_prefix: str,
                             ipv6_gateway: str,
                             ipv4_args: Optional[Ipv4Args],
                             verbose: Optional[str]) -> Path:
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
    assert setupos_inject_configuration_path.exists() and \
        is_executable(setupos_inject_configuration_path)

    invoke.run(f"tar --extract --zstd --file {compressed_image_path} --directory {working_dir}", echo=True)

    img_path = Path(f"{working_dir}/disk.img")
    assert img_path.exists()

    image_part = f"--image-path {img_path}"
    prefix_part = f"--ipv6-prefix {ipv6_prefix}"
    gateway_part = f"--ipv6-gateway {ipv6_gateway}"
    ipv4_part = ""
    if ipv4_args:
        ipv4_part = f"--ipv4-address {ipv4_args.address} "
        ipv4_part += f"--ipv4-gateway {ipv4_args.gateway} "
        ipv4_part += f"--ipv4-prefix-length {ipv4_args.prefix_length} "
        ipv4_part += f"--domain {ipv4_args.domain} "

    verbose_part = ""
    if verbose:
        verbose_part = f"--verbose {verbose} "

    invoke.run(f"{setupos_inject_configuration_path} {image_part} {prefix_part} {gateway_part} {ipv4_part} {verbose_part}", echo=True)

    # Reuse the name of the compressed image path in the working directory
    result_filename = compressed_image_path.name
    result_path = Path(f"{working_dir}/{result_filename}")
    invoke.run(f"tar --create --zstd --file {result_path} --directory {working_dir} {img_path.name}", echo=True)

    return result_path


def get_idrac_script_dir(idrac_script_dir_file: Optional[str]) -> Path:
    if idrac_script_dir_file:
        log.info(f"Using idrac script dir file: {idrac_script_dir_file}")
        idrac_script_dir = open(idrac_script_dir_file).read().strip()
        assert '\n' not in idrac_script_dir, "idrac script dir file must be one line"
        return Path(idrac_script_dir)
    return Path(DEFAULT_IDRAC_SCRIPT_DIR)


def main():
    print(sys.argv)
    args: Args = parse(Args, add_config_path_arg=True) # Parse from config file too

    DISABLE_PROGRESS_BAR = args.ci_mode # noqa - ruff format wants to erroneously delete this

    network_image_url: str = (
        f"{args.file_share_url}:{args.file_share_dir}/{args.file_share_image_filename}"
    )
    log.info(f"Using network_image_url: {network_image_url}")

    idrac_script_dir = get_idrac_script_dir(args.idrac_script_dir_file)
    log.info(f"Using idrac script dir: {idrac_script_dir}")

    csv_filename: str = args.csv_filename
    bmc_infos = parse_from_csv_file(csv_filename, network_image_url)

    ipv4_args = None
    if args.inject_image_ipv4_address:
        ipv4_args = Ipv4Args(args.inject_image_ipv4_address,
                             args.inject_image_ipv4_gateway,
                             args.inject_image_ipv4_prefix_length,
                             args.inject_image_domain)

    if args.upload_img or args.inject_image_ipv6_prefix:
        file_share_endpoint = create_file_share_endpoint(args.file_share_url, args.file_share_username)
        assert_ssh_connectivity(file_share_endpoint, args.file_share_ssh_key)

        if args.inject_image_ipv6_prefix:
            tmpdir = os.getenv("ICOS_TMPDIR")
            if not tmpdir:
                raise RuntimeError("ICOS_TMPDIR env variable not available, should be set in BUILD script.")
            modified_image_path = inject_config_into_image(
                Path(args.inject_configuration_tool),
                Path(tmpdir),
                Path(args.upload_img),
                args.inject_image_ipv6_prefix,
                args.inject_image_ipv6_gateway,
                ipv4_args,
                args.inject_image_verbose
                )

            upload_to_file_share(
                modified_image_path,
                file_share_endpoint,
                args.file_share_dir,
                args.file_share_image_filename,
                args.file_share_ssh_key)

        elif args.upload_img:
            upload_to_file_share(
                args.upload_img,
                file_share_endpoint,
                args.file_share_dir,
                args.file_share_image_filename,
                args.file_share_ssh_key)

    wait_time_mins = args.wait_time
    parallelism = args.parallel
    success = boot_images(
        bmc_infos=bmc_infos,
        parallelism=parallelism,
        wait_time_mins=wait_time_mins,
        idrac_script_dir=idrac_script_dir
    )

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
