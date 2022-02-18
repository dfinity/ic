import json
import subprocess


def get_testnet(testnet):
    """Get info about the given testnet."""
    p = subprocess.run(
        ["ansible-inventory", "-i", "env/{}/hosts".format(testnet), "--list"],
        check=True,
        cwd="../testnet",
        capture_output=True,
    )
    j = json.loads(p.stdout.decode("utf-8"))
    return j


def get_host_for_ip(testnet: str, ip: str):
    """Get host name for the given IP address."""
    j = get_testnet(testnet)
    for (_, info) in j["_meta"]["hostvars"].items():
        if "ipv6" in info and info["ipv6"] == ip:
            return info["ic_host"]
