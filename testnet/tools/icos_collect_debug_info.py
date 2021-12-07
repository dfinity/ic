#!/usr/bin/env python3
"""
Collect various debug information from a testnet test deployment.

- collect system and "ic-replica" service logs using journalctl
- collect replica endpoint status
- collect netstat
- store them in the $experiment_dir/debug_info
The collected debug information can be downloaded from the GitLab Web UI or using the command line:

${REPO_ROOT}/gitlab-ci/src/artifacts/gitlab_artifacts_download.py --job-id <gitlab-job-id>
"""
import argparse
import json
import logging
import os
import pathlib
import subprocess
import typing
from multiprocessing import Pool

import cbor
import git
import paramiko
import requests
import yaml


git_repo = git.Repo(os.path.dirname(__file__), search_parent_directories=True)
repo_root = pathlib.Path(git_repo.git.rev_parse("--show-toplevel"))


def get_deployment_nodes(deployment_name: str):
    """Get a list of nodes for a deployment, as a dictionary of {node_name: ipv6}."""
    output = subprocess.check_output(
        [
            repo_root / "testnet/ansible/inventory/inventory.py",
            "--deployment",
            deployment_name,
            "--nodes",
        ]
    )
    return yaml.load(output, Loader=yaml.FullLoader)


def _get_map_node_to_ic_host(deployment_name: str):
    """Get the mapping {node: phy_node} between the nodes and the raw iron (physical host) behind it."""
    hosts = subprocess.check_output(
        [
            repo_root / "testnet/ansible/inventory/inventory.py",
            "--deployment",
            deployment_name,
            "--list",
        ]
    )
    result = {}
    for phy_host, host_vars in json.loads(hosts)["_meta"]["hostvars"].items():
        # Try to get the list of ic_guests on every hostvars. If the list does not exist, fallback to an empty list.
        for node in host_vars.get("ic_guests", []):
            # There are some "ic_guests" on this physical node, so create a reverse mapping
            result[node] = phy_host
    return result


def collect_host_dominfo(nodes: typing.List[str], deployment_name: str):
    """Iterate through the hosts collecting dominfo for each node and pull the libvirt dominfo for the deployment VMs."""
    node_to_ic_host = _get_map_node_to_ic_host(deployment_name)
    for node_name, node_ipv6 in nodes.items():
        ichost = node_to_ic_host[node_name]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        command = "sudo virsh dominfo " + node_name

        client.connect(ichost, port=22, username=os.environ.get("USER", "gitlab-runner"), timeout=10)

        (_stdin, _stdout, _stderr) = client.exec_command(f"timeout 10 bash -c '{command}'")
        logging.info("-------")
        logging.info("using command _ %s _ on host %s", command, ichost)
        for line in iter(_stdout.readline, ""):
            print(line, end="")


def _ssh_run_command(node: typing.List, out_dir: pathlib.Path, out_filename: str, command: str):
    """SSH into a node, run the command, and store the result in a local file {outdir}/{out_filename}."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if isinstance(out_dir, str):
        out_dir = pathlib.Path(out_dir)

    node_name, node_ipv6 = node
    logging.info("Run for node %s: %s", node_name, command)

    client.connect(node_ipv6, port=22, username="admin", timeout=10)

    (_stdin, stdout, stderr) = client.exec_command(f"timeout 10 bash -c '{command}'")
    node_log_dir = out_dir / node_name
    node_log_dir.mkdir(exist_ok=True, parents=True)
    with open(node_log_dir / out_filename, "wb") as f_stdout:
        stdout.channel.settimeout(10)
        stdout.channel.recv_exit_status()
        f_stdout.write(stdout.read())
    with open(node_log_dir / out_filename, "ab") as f_stderr:
        stderr.channel.settimeout(10)
        stderr.channel.recv_exit_status()
        f_stderr.write(stderr.read())


def _parallel_ssh_run(nodes: typing.List[str], out_dir: pathlib.Path, out_filename: str, command: str):
    """Parallel ssh into the `nodes` and run `command`, then store the output into `out_dir`/{node}/`out_filename`."""
    with Pool(16) as pool:
        pool.starmap(
            _ssh_run_command,
            map(lambda n: (n, out_dir, out_filename, command), nodes.items()),
        )


def collect_journalctl_logs(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the system logs for all nodes in a deployment."""
    _parallel_ssh_run(
        nodes,
        out_dir,
        "journalctl-system.txt",
        "journalctl --since='-24h'",
    )


def collect_ic_replica_service_logs(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the "ic-replica" service logs for all nodes in a deployment."""
    _parallel_ssh_run(
        nodes,
        out_dir,
        "journalctl-ic-replica.txt",
        "journalctl -xu ic-replica --since='-24h'",
    )


def collect_netstat_listen_ports(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the netstat listen ports for all nodes in a deployment."""
    _parallel_ssh_run(nodes, out_dir, "ports-tcp-listen.txt", "sudo netstat -tulpn")


def collect_netstat_open_ports(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the netstat open ports for all nodes in a deployment."""
    _parallel_ssh_run(nodes, out_dir, "ports-tcp-open.txt", "sudo netstat -pn")


def collect_system_stats(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the netstat open ports for all nodes in a deployment."""
    _parallel_ssh_run(nodes, out_dir, "system-stats.txt", "uptime; free -m; ps -faux")


def collect_replica_api_status(nodes: typing.List[str], out_dir: pathlib.Path):
    """Collect the "replica" endpoint status for all nodes in a deployment."""
    for node_name, node_ipv6 in nodes.items():
        node_log_dir = out_dir / node_name
        node_log_dir.mkdir(exist_ok=True, parents=True)

        replica_url = f"http://[{node_ipv6}]:8080/api/v2/status"
        try:
            req = requests.get(replica_url)

            with open(node_log_dir / "replica-status.cbor", "wb") as f_out:
                f_out.write(req.content)

            status = cbor.loads(req.content)
            with open(node_log_dir / "replica-status.txt", "w") as f_out:
                f_out.write(str(status.value))

        except requests.exceptions.ConnectionError as e:
            with open(node_log_dir / "replica-status.txt", "w") as f_out:
                f_out.write("ConnectionError: %s" % e)


def collect_all_debug_info(
    deployment_name: str,
    out_dir: pathlib.Path,
):
    """Collect the debug info for a deployment and store it in out_dir."""
    nodes = get_deployment_nodes(deployment_name)
    if isinstance(out_dir, str):
        out_dir = pathlib.Path(out_dir)

    logging.info("Collecting debug info for the IC-OS deployment: %s", deployment_name)
    out_dir.mkdir(exist_ok=True, parents=True)
    paramiko.util.log_to_file(out_dir / "paramiko.log", level="WARN")

    collect_host_dominfo(nodes, deployment_name)
    collect_journalctl_logs(nodes, out_dir)
    collect_ic_replica_service_logs(nodes, out_dir)
    collect_replica_api_status(nodes, out_dir)
    collect_netstat_listen_ports(nodes, out_dir)
    collect_netstat_open_ports(nodes, out_dir)
    collect_system_stats(nodes, out_dir)

    logging.info("Debug info written to: %s", out_dir.absolute())


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--deployment-name",
        action="store",
        help='Deployment name (e.g. "cdhourly")',
    )

    parser.add_argument(
        "--out-dir",
        action="store",
        help="The directory where the debug information should be written.",
        default=pathlib.Path("."),
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    collect_all_debug_info(args.deployment_name, out_dir=args.out_dir)


if __name__ == "__main__":
    main()
