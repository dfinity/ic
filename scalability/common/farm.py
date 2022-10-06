#!/usr/bin/python3
import getpass
import itertools
import os
import subprocess
import sys
import time

import gflags
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import ssh  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string("farm_group_name", None, "Farm group name to use. Default is testvm-$user-$time")
gflags.DEFINE_string("ci_runner_tags", None, "Allocate VMs close to the CI runner, when running on CI")

FARM_BASE_URL = "https://farm.dfinity.systems"
TTL = 3600

DOWNLOAD_BASE_URL = "http://download.proxy-global.dfinity.network:8080"
DISK_IMAGE = "disk-img.tar.zst"
DISK_IMAGE_KIND = "disk-img-dev"


def url_from_git_commit(git_rev: str):
    return f"{DOWNLOAD_BASE_URL}/ic/{git_rev}"


def image_url_from_git_commit(git_rev: str):
    url = url_from_git_commit(git_rev)
    return f"{url}/guest-os/{DISK_IMAGE_KIND}/{DISK_IMAGE}"


def get_allocation() -> str:
    ci_runner_tags = FLAGS.ci_runner_tags
    if ci_runner_tags is not None:
        try:
            import json

            tags = json.loads(ci_runner_tags)
            if "zh" in tags:
                return ["dc=zh1"]
            if "ch" in tags:
                return ["dc=ch1"]
            if "sf" in tags:
                return ["dc=sf1"]

        except Exception:
            print("Failed to get_allocation from CI_RUNNER_TAGS, using default")
            return ["dc=zh1"]
    else:
        return ["dc=zh1"]


def get_ic_os_image_sha(img_base_url, filename=None) -> str:
    if filename is None:
        filename = DISK_IMAGE
    if img_base_url[-1] != "/":
        img_base_url += "/"
    img_sha256_url = f"{img_base_url}SHA256SUMS"
    result = requests.get(f"{img_sha256_url}")
    print(f"GET {img_sha256_url} responded with status_code={result.status_code}.")
    if result.status_code != 200:
        raise Exception(f"Unexpected status_code={result.status_code} for the GET {img_sha256_url}")
    hashes = {}
    for line in result.text.splitlines():
        parts = line.split(" ")
        sha256hex = parts[0]
        name = parts[1][1:]
        hashes[name] = sha256hex
    img_sha256 = hashes[filename]
    return img_sha256


def sha256_for_image(git_rev: str):
    return get_ic_os_image_sha(url_from_git_commit(git_rev) + f"/guest-os/{DISK_IMAGE_KIND}/")


# https://farm.dfinity.systems/swagger-ui/#/default/post_group__group_name_
# https://github.com/dfinity-lab/farm/
class Farm(object):
    def __init__(self, artifacts_path, subnet_config: [int], version: str):
        """
        subnet_config: array of subnets, with the number of nodes per subnet,
        e.g. [1, 2] for one subnet of 1 node and another subnet with 2 nodes.
        """
        self.artifacts_path = artifacts_path
        self.version = version
        self.subnet_config = subnet_config

        if FLAGS.farm_group_name is not None:
            self.group_name = FLAGS.farm_group_name
        else:
            if "CI_PIPELINE_ID" in os.environ:
                test_id = os.environ["CI_PIPELINE_ID"]
            else:
                now = time.strftime("%Y-%M-%d-%H-%m-%S")
                test_id = getpass.getuser() + "-" + now
            self.group_name = "scalability-suite-" + test_id
        self.group_url = FARM_BASE_URL + "/group/" + self.group_name

        self.expiry = None
        self.ipv6 = None
        self.vm_url = []
        self.ic_config = None

    def create_farm_group(self):
        print("Setting up farm group")
        self.delete_farm_group()
        # Create group
        response = requests.post(
            self.group_url,
            json={"ttl": TTL, "spec": {}},
            headers={"accept": "application/json"},
        )
        if response.status_code >= 400:
            print("Response:", response.text)
        response.raise_for_status()
        self.expiry = response.json()["expiresAt"]
        print("Farm group expires at", self.expiry)

    def delete_farm_group(self):
        """Delete a previously created farm group."""
        # Delete old group (ignoring error)
        print(f"Deleting farm group {self.group_url}")
        _ = requests.delete(self.group_url)

    def setup_disk_image(self, url, img_hash):
        """Set up VM using image uploaded previously."""
        print("Setting up VMs using disk image %s" % url)
        self.ipv6 = []
        for subnet_idx, num_nodes in enumerate(self.subnet_config):
            subnet_ips = []
            for machine_idx in range(num_nodes):
                primary_image = {"_tag": "icOsImageViaUrl", "url": url, "sha256": img_hash}

                self.vm_url.append(self.group_url + f"/vm/machine-{subnet_idx}-{machine_idx}")

                allocation = get_allocation()
                print(f"Using allocation: {allocation}")
                response = requests.post(
                    self.vm_url[-1],
                    json={
                        "type": "production",
                        "vCPUs": 2,
                        "memoryKiB": 25165824,
                        "primaryImage": primary_image,
                        "primaryImageMinimalSizeGiB": 100,
                        "requiredHostFeatures": allocation,
                    },
                    headers={"accept": "application/json"},
                )
                if response.status_code != 200:
                    raise Exception(f"Unexpected status_code={response.status_code}, {response.text}")

                subnet_ips.append(response.json()["ipv6"])
            self.ipv6.append(subnet_ips)

    def prepare_and_register_config_image(self):
        print(f"Setting up config image with {self.ipv6}")
        assert self.ipv6 is not None

        sys.path.insert(1, "../ic-os/guestos/tests")
        import ictools

        # Generate config image
        FLAGS.ic_prep_bin = os.path.join(self.artifacts_path, "ic-prep")
        self.ic_config = ictools.ic_prep(
            subnets=self.ipv6,
            version=self.version,
            root_subnet=0,
        )

        for machine_idx, (ipv6_address, vm_url) in enumerate(zip(itertools.chain(*self.ipv6), self.vm_url)):
            extra_config = ictools.build_ssh_extra_config()
            extra_config.update(
                {
                    "ipv6_address": ipv6_address,
                }
            )

            if "TEST_ES_HOSTNAMES" in os.environ:
                extra_config["journalbeat_hosts"] = os.environ["TEST_ES_HOSTNAMES"].replace(",", " ")

            extra_config["journalbeat_tags"] = f"scalability_suite {self.group_name}"

            config_image = ictools.build_ic_prep_inject_config(
                self.ic_config,
                machine_idx,
                extra_config,
            )
            os.system("gzip " + config_image)
            response = requests.post(
                self.group_url + "/file",
                files={"config": open(config_image + ".gz", "rb").read()},
                headers={"accept": "application/json"},
            )
            response.raise_for_status()
            config_image_id = response.json()["fileIds"]["config"]
            requests.put(
                vm_url + "/drive-templates/usb-storage",
                json={"drives": [{"_tag": "imageViaId", "id": config_image_id}]},
                headers={"accept": "application/json"},
            )
            response.raise_for_status()

    def start_vm(self):
        print("Starting VM")
        for vm_url, ipv6 in zip(self.vm_url, itertools.chain(*self.ipv6)):
            response = requests.put(vm_url + "/start")
            response.raise_for_status()

            print("Serial console at %s/console" % vm_url)
            print("Connect to system via ssh admin@%s" % ipv6)

    def wait_replica_up(self):
        vm_ipv6_addresses = list(itertools.chain(*self.ipv6))
        num_vms = len(vm_ipv6_addresses)
        results = [1] * num_vms
        tries = 0
        while results != [0] * num_vms and tries < 20:
            time.sleep(20)
            results = ssh.run_all_ssh_in_parallel(
                vm_ipv6_addresses, ["systemctl status ic-replica"] * num_vms, timeout=20
            )
            tries += 1
        return results == [0] * num_vms

    def latest_with_disk_image():
        cmd = subprocess.check_output(["../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh", "origin/master"])
        return cmd.decode().strip("\n")


def main(argv):
    farm = None
    argv = FLAGS(argv)
    version = Farm.latest_with_disk_image()
    farm = Farm("../artifacts/release", [1, 1], version)
    try:
        farm.create_farm_group()
        farm.setup_disk_image(image_url_from_git_commit(version), sha256_for_image(version))
        farm.prepare_and_register_config_image()
        farm.start_vm()
        farm.wait_replica_up()
    finally:
        farm.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
