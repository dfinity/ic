#!/usr/bin/env python3
import atexit
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import cbor
import gflags
import requests

FLAGS = gflags.FLAGS

gflags.DEFINE_string("ic_prep_bin", None, "Path to ic-prep binary")
gflags.DEFINE_string("install_nns_bin", None, "Path to ic-nns-init bin")
gflags.DEFINE_integer("timeout", 240, "Timeout in seconds to wait for IC to come up")
gflags.DEFINE_string("nns_canisters", None, "Path to directory with NNS canisters wasm files")


class ICConfig(object):
    """Store configuration for an instance of the Internet Computer."""

    def __init__(self, workdir, nns_ips, node_subnet_index, root_subnet):
        """Initialize an IC with the given settings."""
        self.workdir = workdir
        self.nns_ips = list(nns_ips)
        self.node_subnet_index = node_subnet_index
        self.root_subnet = root_subnet


def build_bootstrap_config_image(name, **kwargs):
    config_image_dir = tempfile.mkdtemp()
    atexit.register(lambda: shutil.rmtree(config_image_dir))
    config_image = os.path.join(config_image_dir, "config-%s.img" % name)

    if "accounts_ssh_authorized_keys" in kwargs:
        accounts_ssh_authorized_keys = kwargs["accounts_ssh_authorized_keys"]
        ssh_keys_dir = tempfile.mkdtemp()
        atexit.register(lambda: shutil.rmtree(ssh_keys_dir))
        for account, keyfile in accounts_ssh_authorized_keys.items():
            with open(keyfile) as f:
                keys = f.read()
            with open(os.path.join(ssh_keys_dir, account), "w") as f:
                f.write(keys)
        kwargs["accounts_ssh_authorized_keys"] = ssh_keys_dir

    p = Path(__file__).parents[2]
    bootstrap_script = os.path.join(p, "ic-os/components/hostos-scripts/build-bootstrap-config-image.sh")
    args = [bootstrap_script, config_image]
    for key, value in kwargs.items():
        args.append("--" + key)
        args.append(value)
    subprocess.run(args, stdout=subprocess.DEVNULL, check=True)
    return config_image


def get_ic_version(replica_url):
    timeout = 5
    start = time.time()
    now = start
    while now < start + timeout:
        try:
            req = requests.get(replica_url)
            status = cbor.loads(req.content)
            return status.value["impl_version"]
        except Exception as e:
            print(e)
            time.sleep(1)
            now = time.time()
    raise TimeoutError("Failed to determine IC version.")


def ic_prep(subnets, version, root_subnet=0):
    workdir = tempfile.mkdtemp()
    atexit.register(lambda workdir=workdir: shutil.rmtree(workdir))

    nns_ips = []
    nodes = []
    node_index = 0
    subnet_index = 0
    node_subnet_index = []
    for subnet in subnets:
        for ipv6 in subnet:
            nodes.append("--node")
            nodes.append("idx:%d,subnet_idx:%d,xnet_api:\"[%s]:2497\",public_api:\"[%s]:8080\"" % (node_index, subnet_index, ipv6, ipv6))
            if subnet_index == root_subnet:
                nns_ips.append(ipv6)
            node_subnet_index.append(subnet_index)
            node_index += 1
        subnet_index += 1

    tmpfile = tempfile.NamedTemporaryFile(delete=False)
    tmpfile.write("{provisional_whitelist: ['*']}".encode())
    tmpfile.close()

    subprocess.run(
        [
            FLAGS.ic_prep_bin,
            "--working-dir",
            workdir,
            "--replica-version",
            version,
            "--allow-empty-update-image",
            "--provisional-whitelist",
            tmpfile.name,
            "--dkg-interval-length",
            "10",
            "--nns-subnet-index",
            "%d" % root_subnet,
        ]
        + nodes,
        check=True,
    )

    os.unlink(tmpfile.name)

    return ICConfig(workdir, nns_ips, node_subnet_index, root_subnet)


def build_ic_prep_inject_config(ic_config, index, extra_config={}):
    args = {
        "nns_url": "http://[%s]:8080" % ic_config.nns_ips[0],
        "nns_public_key": os.path.join(ic_config.workdir, "nns_public_key.pem"),
        "ic_crypto": os.path.join(ic_config.workdir, "node-%d" % index, "crypto"),
    }
    if ic_config.node_subnet_index[index] == ic_config.root_subnet:
        args["ic_registry_local_store"] = os.path.join(ic_config.workdir, "ic_registry_local_store")
    args.update(extra_config)

    return build_bootstrap_config_image("foo", **args)


def nns_install(ic_config, ic_url):
    cmd = [
        "timeout",
        "120",
        FLAGS.install_nns_bin,
        "--url",
        ic_url,
        "--registry-local-store-dir",
        "%s/ic_registry_local_store" % ic_config.workdir,
        "--wasm-dir",
        FLAGS.nns_canisters,
    ]
    return subprocess.run(cmd, check=True)


def wait_http_up(url, timeout=None):
    if timeout is None:
        timeout = FLAGS.timeout
    start = time.time()
    now = start
    while now < start + timeout:
        try:
            requests.get(url)
            return
        except Exception:
            sys.stderr.write(
                ("Waiting for IC to come up at %s, retrying for next %.1f seconds\n" % (url, start + timeout - now))
            )
            sys.stderr.flush()
            time.sleep(1)
            now = time.time()
    raise TimeoutError("Time out waiting for IC instance to come up.")


def build_ssh_extra_config():
    """
    Build extra config containing ssh keys.

    Build an amendent to the IC guest OS bootstrap config that contains
    ssh keys for accessing the node. If there are no ssh keys existing
    yet (this is the case for CI runners), also create ssh keys.
    """
    # Ensure that $HOME/.ssh/id_rsa.pub exists
    home_dir = os.path.expanduser("~" + getpass.getuser())
    home_ssh = os.path.join(home_dir, ".ssh")
    id_rsa_pub = os.path.join(home_ssh, "id_rsa.pub")

    if not os.path.exists(home_ssh):
        os.mkdir(home_ssh)
    if not os.path.exists(id_rsa_pub):
        subprocess.run(
            ["ssh-keygen", "-q", "-N", "", "-f", os.path.join(home_ssh, "id_rsa")],
            check=True,
        )

    # Assign keys to root user so we have root login on the node.
    return {
        "accounts_ssh_authorized_keys": {
            "root": id_rsa_pub,
            "backup": id_rsa_pub,
            "readonly": id_rsa_pub,
            "admin": id_rsa_pub,
        }
    }
