#!/usr/bin/python3
import getpass
import itertools
import json
import os
import stat
import subprocess
import sys
import time
import uuid
from typing import List

import gflags
import paramiko
import requests
import scp

this_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(this_script_dir))
from common import ssh  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string("farm_group_name", None, "Farm group name to use. Default is testvm-$user-$time")
gflags.DEFINE_string("ci_runner_tags", None, "Allocate VMs close to the CI runner, when running on CI")
gflags.DEFINE_integer("farm_ttl_secs", 3600, "VM expiry in seconds")

FARM_BASE_URL = "https://farm.dfinity.systems"

DOWNLOAD_BASE_URL = "http://download.proxy-global.dfinity.network:8080"
DISK_IMAGE = "disk-img.tar.zst"
DISK_IMAGE_KIND = "disk-img-dev"
DEFAULT_NUM_VCPUS = 2

# The SHA-256 hash of the Prometheus VM disk image.
# The latest hash can be retrieved by downloading the SHA256SUMS file from:
# https://hydra.dfinity.systems/job/dfinity-ci-build/farm/universal-vm.img-prometheus.x86_64-linux/latest
#
# Please also keep this in sync with the DEFAULT_PROMETHEUS_VM_IMG_SHA256 constant in:
# rs/tests/src/driver/prometheus_vm.rs
PROMETHEUS_VM_DISK_IMG_SHA256 = "209b6e695adcea30edf70910abfd5f93d4462ca1eaa91774c8bd1c7f02f07e4d"
PROMETHEUS_VM_DISK_IMG_URL = (
    f"{DOWNLOAD_BASE_URL}/farm/prometheus-vm/{PROMETHEUS_VM_DISK_IMG_SHA256}/x86_64-linux/prometheus-vm.img.zst"
)


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


def write_json_to_file(filepath, obj):
    with open(filepath, "w") as f:
        json.dump(obj, f)


def prepare_prometheus_vm_config_image_file(group_name, ic_node_ipv6s) -> str:
    config_dir = "prometheus_vm/config_dir"
    os.makedirs(config_dir, exist_ok=False)

    # First generate a SSH key-pair where the public key is stored in the config image
    # and the private key in ./prometheus_vm/ssh_keys. This allows the script to SSH into
    # the prometheus-vm via the "admin" user later on.
    ssh_dir = "prometheus_vm/ssh_keys"
    os.makedirs(ssh_dir, exist_ok=False)
    gen_key_command = [
        "ssh-keygen",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        f"{ssh_dir}/admin",
    ]
    process = subprocess.run(gen_key_command)
    if process.returncode != 0:
        raise Exception(f"Generation of ssh keys failed with code={process.returncode}")
    os.makedirs(f"{config_dir}/ssh-authorized-keys", exist_ok=False)
    os.rename(f"{ssh_dir}/admin.pub", f"{config_dir}/ssh-authorized-keys/admin")

    # Create a no-op activate file. We could later add some custom logic here
    # which will be executed on boot.
    script = "#!/bin/sh"
    file_activate = f"{config_dir}/activate"
    with open(file_activate, "w") as f:
        f.write(script)
    st = os.stat(file_activate)
    os.chmod(file_activate, st.st_mode | stat.S_IEXEC)

    # Generate prometheus configuration.
    prometheus_config_dir = os.path.join(config_dir, "prometheus")
    os.makedirs(prometheus_config_dir, exist_ok=False)
    write_json_to_file(
        os.path.join(prometheus_config_dir, "prometheus.yml"),
        {
            "global": {"scrape_interval": "1s"},
            "scrape_configs": [
                {"job_name": "replica", "file_sd_configs": [{"files": ["/config/prometheus/replica.json"]}]},
                {"job_name": "orchestrator", "file_sd_configs": [{"files": ["/config/prometheus/orchestrator.json"]}]},
                {
                    "job_name": "node_exporter",
                    "file_sd_configs": [{"files": ["/config/prometheus/node_exporter.json"]}],
                    "scheme": "https",
                    "tls_config": {"insecure_skip_verify": True},
                },
            ],
        },
    )
    job_ports = {
        "orchestrator": 9091,
        "node_exporter": 9100,
    }
    for job, port in job_ports.items():
        write_json_to_file(
            os.path.join(prometheus_config_dir, f"{job}.json"),
            [
                {
                    "targets": [f"[{ipv6}]:{port}" for subnet_ipv6s in ic_node_ipv6s for ipv6 in subnet_ipv6s],
                    "labels": {
                        "ic": group_name,
                    },
                }
            ],
        )
    write_json_to_file(
        os.path.join(prometheus_config_dir, "replica.json"),
        [
            {
                "targets": [f"[{ipv6}]:9090"],
                "labels": {
                    "ic": group_name,
                    "ic_node": f"node-{node_ix}",
                    "ic_subnet": f"subnet-{subnet_ix}",
                },
            }
            for subnet_ix, subnet_ipv6s in enumerate(ic_node_ipv6s)
            for node_ix, ipv6 in enumerate(subnet_ipv6s)
        ],
    )

    # Create the image.
    file_name = f"{config_dir}/image_output"
    create_universal_vm_config_image_script_path = os.path.join(
        this_script_dir, "../../rs/tests/create-universal-vm-config-image.sh"
    )
    command = [
        create_universal_vm_config_image_script_path,
        "--input",
        config_dir,
        "--output",
        file_name,
    ]
    process = subprocess.run(command)
    if process.returncode != 0:
        raise Exception(
            f"Create image script {create_universal_vm_config_image_script_path} failed with code={process.returncode}."
        )
    return file_name


# https://farm.dfinity.systems/swagger-ui/#/default/post_group__group_name_
# https://github.com/dfinity-lab/farm/
class Farm(object):
    def __init__(self, artifacts_path, subnet_config: List[int], version: str):
        """
        version: the version of the IC to deploy. Needs to match the contents of
        version.txt in the IC-OS image.
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
                test_id = getpass.getuser() + "-" + now + "-" + str(uuid.uuid4())
            self.group_name = "scalability-suite-" + test_id
        self.group_url = FARM_BASE_URL + "/group/" + self.group_name
        self.prometheus_vm_url = f"{self.group_url}/vm/prometheus"
        self.prometheus_ipv6 = None

        self.expiry = None
        self.ic_node_ipv6s = None
        self.ic_node_urls = []
        self.ic_config = None

    def create_farm_group(self):
        print("Setting up farm group")
        self.delete_farm_group()
        # Create group
        response = requests.post(
            self.group_url,
            json={"ttl": FLAGS.farm_ttl_secs, "spec": {}},
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

    def create_vms_from_ic_os_image_via_url(self, url, img_hash, num_vcpus={}):
        """Set up VMs using IC-OS image uploaded previously."""
        print("Setting up VMs using disk image %s" % url)
        self.ic_node_ipv6s = []
        for subnet_idx, num_nodes in enumerate(self.subnet_config):
            subnet_ips = []
            for machine_idx in range(num_nodes):
                primary_image = {"_tag": "icOsImageViaUrl", "url": url, "sha256": img_hash}

                self.ic_node_urls.append(self.group_url + f"/vm/machine-{subnet_idx}-{machine_idx}")

                allocation = get_allocation()
                print(f"Using allocation: {allocation}")
                response = requests.post(
                    self.ic_node_urls[-1],
                    json={
                        "type": "production",
                        "vCPUs": num_vcpus.get(subnet_idx, DEFAULT_NUM_VCPUS),
                        "memoryKiB": 25_165_824,
                        "primaryImage": primary_image,
                        "primaryImageMinimalSizeGiB": 100,
                        "requiredHostFeatures": allocation,
                    },
                    headers={"accept": "application/json"},
                )
                if response.status_code != 200:
                    raise Exception(f"Unexpected status_code={response.status_code}, {response.text}")

                subnet_ips.append(response.json()["ipv6"])
            self.ic_node_ipv6s.append(subnet_ips)

    def create_prometheus_vm(self):
        response = requests.post(
            self.prometheus_vm_url,
            json={
                "type": "production",
                "vCPUs": 2,
                "memoryKiB": 25_165_824,  # 25 GiB
                "primaryImage": {
                    "_tag": "imageViaUrl",
                    "url": PROMETHEUS_VM_DISK_IMG_URL,
                    "sha256": PROMETHEUS_VM_DISK_IMG_SHA256,
                },
                "primaryImageMinimalSizeGiB": 50,
                "requiredHostFeatures": get_allocation(),
            },
            headers={"accept": "application/json"},
        )
        self.prometheus_ipv6 = response.json()["ipv6"]

    def prepare_and_register_prometheus_config_image(self):
        config_image = prepare_prometheus_vm_config_image_file(self.group_name, self.ic_node_ipv6s)

        with open(config_image, "rb") as f:
            response = requests.post(
                self.group_url + "/file",
                files={"config": f.read()},
                headers={"accept": "application/json"},
            )
        response.raise_for_status()
        config_image_id = response.json()["fileIds"]["config"]
        requests.put(
            self.prometheus_vm_url + "/drive-templates/usb-storage",
            json={"drives": [{"_tag": "imageViaId", "id": config_image_id}]},
            headers={"accept": "application/json"},
        )
        response.raise_for_status()

    def start_prometheus_vm(self):
        response = requests.put(f"{self.prometheus_vm_url}/start")
        response.raise_for_status()
        print(f"Prometheus-vm's serial console at {self.prometheus_vm_url}/console")
        print(f"Prometheus Web UI at http://[{self.prometheus_ipv6}]:9090")
        print(f"Grafana at http://[{self.prometheus_ipv6}]:3000")

    def download_prometheus_data_dir(self):
        destination = "prometheus_vm/prometheus-data-dir.tar.zst"
        print(f"Downloading prometheus' data directory to {destination} ...")
        with paramiko.SSHClient() as ssh_client:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                self.prometheus_ipv6,
                username="admin",
                key_filename="prometheus_vm/ssh_keys/admin",
            )
            channel = ssh_client.get_transport().open_session()
            tarball = "/home/admin/prometheus-data-dir.tar.zst"
            channel.exec_command(
                f"""
                    sudo systemctl stop prometheus.service &&
                    sudo tar -cf "{tarball}" \
                        --sparse \
                        --use-compress-program="zstd --threads=0 -10" \
                        -C /var/lib/prometheus .
                """
            )
            exit_status = channel.recv_exit_status()
            if exit_status != 0:
                raise Exception(f"Unexpected exit_status={exit_status} when packaging the prometheus data directory!")

            with scp.SCPClient(ssh_client.get_transport()) as scp_client:
                scp_client.get(tarball, local_path=destination)

    def prepare_and_register_config_image(self):
        print(f"Setting up config image with {self.ic_node_ipv6s}")
        assert self.ic_node_ipv6s is not None

        sys.path.insert(1, "../ic-os/guestos/tests")
        import ictools

        # Generate config image
        FLAGS.ic_prep_bin = os.path.join(self.artifacts_path, "ic-prep")
        self.ic_config = ictools.ic_prep(
            subnets=self.ic_node_ipv6s,
            version=self.version,
            root_subnet=0,
        )

        for machine_idx, (ipv6_address, vm_url) in enumerate(
            zip(itertools.chain(*self.ic_node_ipv6s), self.ic_node_urls)
        ):
            extra_config = ictools.build_ssh_extra_config()

            if "TEST_ES_HOSTNAMES" in os.environ:
                extra_config["journalbeat_hosts"] = os.environ["TEST_ES_HOSTNAMES"].replace(",", " ")

            extra_config["journalbeat_tags"] = f"scalability_suite {self.group_name}"

            config_image = ictools.build_ic_prep_inject_config(
                self.ic_config,
                machine_idx,
                extra_config,
            )
            os.system("gzip " + config_image)
            with open(config_image + ".gz", "rb") as f:
                response = requests.post(
                    self.group_url + "/file",
                    files={"config": f.read()},
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

    def start_ic_node_vms(self):
        print("Starting VM")
        for vm_url, ipv6 in zip(self.ic_node_urls, itertools.chain(*self.ic_node_ipv6s)):
            response = requests.put(vm_url + "/start")
            response.raise_for_status()

            print("Serial console at %s/console" % vm_url)
            print("Connect to system via ssh admin@%s" % ipv6)

    def wait_replica_up(self):
        vm_ipv6_addresses = list(itertools.chain(*self.ic_node_ipv6s))
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
        farm.create_vms_from_ic_os_image_via_url(image_url_from_git_commit(version), sha256_for_image(version))
        farm.prepare_and_register_config_image()
        farm.start_ic_node_vms()
        farm.wait_replica_up()
    finally:
        farm.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
