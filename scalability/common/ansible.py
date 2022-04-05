import json
import os
import subprocess

import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    "hosts_ini_filename", "hosts.ini", "hosts.ini file to used for the testnet deployment, if done via ansible"
)


def get_ansible_inventory(testnet):
    """Return the json-parsed ansible inventory for the given testnet."""
    ansible_env = os.environ.copy()
    ansible_env["HOSTS_INI_FILENAME"] = FLAGS.hosts_ini_filename
    p = subprocess.run(
        ["ansible-inventory", "-i", "env/{}/hosts".format(testnet), "--list"],
        check=True,
        cwd="../testnet",
        capture_output=True,
        env=ansible_env,
    )
    j = json.loads(p.stdout.decode("utf-8"))
    return j


def get_host_for_ip(testnet: str, ip: str):
    """Get host name for the given IP address."""
    j = get_ansible_inventory(testnet)
    for (_, info) in j["_meta"]["hostvars"].items():
        if "ipv6" in info and info["ipv6"] == ip:
            return info["ic_host"]


def get_ansible_machine_info_for_subnet(testnet, subnet=0):
    """Get a list of ansible machine configurations for the given subnetwork and testnet."""
    j = get_ansible_inventory(testnet)
    hosts = [
        info
        for (_, info) in j["_meta"]["hostvars"].items()
        if "subnet_index" in info and info["subnet_index"] == subnet
    ]
    return hosts


def get_ansible_hostnames_for_subnet(testnet, subnet=0, sort=True):
    """Return hostnames of all machines in the given testnet and subnet from ansible files."""
    hosts = [h["ansible_host"] for h in get_ansible_machine_info_for_subnet(testnet, subnet)]
    if sort:
        hosts = sorted(hosts)
    return hosts
