import os
import re
import shlex
import subprocess
import sys
import time
import traceback

import gflags
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import farm  # noqa
from common import misc  # noqa
from common import ssh  # noqa

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ic-os/guestos/tests",
    )
)
import ictools  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_boolean("clean", False, "Set true to do a clean Bazel build")


def get_ic_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_icos():
    # We probably actually want to serve the file from a locally spawned HTTP server instead of this ..
    ic_root = get_ic_root()
    if FLAGS.clean:
        print(colored("Doing clean build", "green"))
        subprocess.check_output(shlex.split("gitlab-ci/tools/docker-run bazel clean"), cwd=ic_root)
        subprocess.check_output(
            shlex.split("gitlab-ci/tools/docker-run rm -rf $(bazel info repository_cache)"), cwd=ic_root
        )
    else:
        print(
            colored(
                (
                    "Doing cached build - due to bugs in Bazel, this might wrongly use a cached IC-OS, "
                    "so make sure the IC version above matches your GIT revision number - "
                    "Set --clean=True for a clean rebuild."
                    "(https://dfinity.slack.com/archives/C0370Q369QW/p1668596127090279)"
                ),
                "red",
            )
        )

    subprocess.check_output(
        shlex.split("gitlab-ci/tools/docker-run bazel run //ic-os/guestos/dev:upload_disk-img"), cwd=ic_root
    )
    version = None
    url = None
    sha256_url = None
    with open(os.path.join(ic_root, "bazel-bin/ic-os/guestos/dev/upload_disk-img.urls")) as f:
        for line in f.readlines():
            print(line)
            m = re.match(
                r"https://download.dfinity.systems/ic/([0-9a-z\-]+)/guest-os/disk-img-dev/disk.img.tar.zst", line
            )
            if m:
                url = line.strip()
                print(f"Found match: {version} for {url}")

            m = re.match(r"https://download.dfinity.systems/ic/([0-9a-z\-]+)/guest-os/disk-img-dev/SHA256SUMS", line)
            if m:
                sha256_url = line.strip()
                print(f"Determining sha256 sum from : {sha256_url}")

    version = open(os.path.join(ic_root, "bazel-bin/ic-os/guestos/dev/version.txt"), "r").read().strip()
    print(colored(f"Running version {version}", "blue"))

    sha256 = (
        subprocess.check_output(f"curl -L -s {sha256_url} | awk '/zst$/ {{print $1}}'", shell=True).decode().split()[0]
    )
    # Alternative, in case above is incorrect:
    # sha256 = subprocess.check_output(f"curl -L -s {url} | sha256sum", shell=True).decode().split()[0]

    print(f"sha256sum is [{sha256}]")
    return (version, url, sha256)


def deploy_farm(farm_instance, url, sha256sum, install_nns=False, num_vcpus={}):
    print(f"Deploying Farm from URL: {url} ")
    farm_instance.create_farm_group()
    farm_instance.create_vms_from_ic_os_image_via_url(url, sha256sum, num_vcpus)
    farm_instance.prepare_and_register_config_image()
    farm_instance.start_ic_node_vms()
    if not farm_instance.wait_replica_up():
        print("Warning: Could not verify that IC replica is up, continuing anyway  .. ")

    ic_ip = farm_instance.ic_node_ipv6s[0][0]
    ic_url = f"http://[{ic_ip}]:8080"
    if install_nns:
        try:
            FLAGS.install_nns_bin = "../artifacts/release/ic-nns-init"
            FLAGS.nns_canisters = "../artifacts/canisters"
            ictools.wait_http_up(ic_url)
            ictools.nns_install(farm_instance.ic_config, ic_url)
        except Exception:
            print("Failed to wait for replica - likely there is an error with this deployment")
            print(traceback.format_exc())

            args = ssh.get_ssh_args(ic_ip, "journalctl -u ic-replica")
            pout = subprocess.check_output(args)
            print(pout)

            # Handle some of the more frequent issues here. We should add to this list.
            if "Starting version upgrade at CUP registry" in pout:
                print("Seems like the replica is stuck in an upgrade loop. Incorrect version number?")

    return ic_ip


def main(argv):
    argv = FLAGS(argv)

    t_start = time.time()
    version, download_url, sha256sum = build_icos()
    input("Hit enter to confirm .. ")
    duration_build = time.time() - t_start
    print(f"Duration for building: {duration_build}")

    misc.load_artifacts("../artifacts/release")

    # Basically the suite will pick the first application subnetwork to target.
    target_instance = farm.Farm("../artifacts/release", [1, 1], version)
    wg_instance = farm.Farm("../artifacts/release", [1], version)

    try:
        # We should really deploy those concurrently.
        target_ip = deploy_farm(target_instance, download_url, sha256sum, install_nns=True, num_vcpus={1: 48})
        wg_ip = deploy_farm(wg_instance, download_url, sha256sum)
        print(
            (
                "IC workload experiments: "
                + colored(
                    (
                        f"--targets={target_instance.ic_node_ipv6s[1][0]} --workload_generator_machines={wg_ip} "
                        f"--testnet=none --wg_testnet=none --no_prometheus=True --no_instrument=True "
                        f"--nns_url=http://[{target_ip}]:8080"
                    ),
                    "red",
                )
            )
        )
        print(
            (
                "IC base experiments: "
                + colored(
                    (
                        f"--targets={target_instance.ic_node_ipv6s[1][0]} "
                        f"--testnet=none --no_prometheus=True --no_instrument=True "
                        f"--nns_url=http://[{target_ip}]:8080"
                    ),
                    "red",
                )
            )
        )
        print(
            (
                f"Base experiments: "
                f"--testnet=none --no_prometheus=True --no_instrument=True "
                f"--nns_url=http://[{target_ip}]:8080"
            )
        )

        duration = time.time() - t_start
        print(f"Deployment finished at: {duration}s")
        print("Sleeping for 1h. CTRL+C to terminate immediately")
        time.sleep(FLAGS.farm_ttl_secs)

    finally:
        target_instance.delete_farm_group()
        wg_instance.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
