import json
import os
import subprocess

import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    "hosts_ini_filename", "hosts.ini", "hosts.ini file to used for the testnet deployment, if done via ansible"
)


def get_testnet(testnet):
    """Get info about the given testnet."""
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
    j = get_testnet(testnet)
    for (_, info) in j["_meta"]["hostvars"].items():
        if "ipv6" in info and info["ipv6"] == ip:
            return info["ic_host"]
