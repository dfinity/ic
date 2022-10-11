import os
import re
import shlex
import subprocess
import sys
import time

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import farm  # noqa
from common import misc  # noqa

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ic-os/guestos/tests",
    )
)
import ictools  # noqa

FLAGS = gflags.FLAGS


def get_ic_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_icos():
    # We probably actually want to serve the file from a locally spawned HTTP server instead of this ..
    ic_root = get_ic_root()
    subprocess.check_output(
        shlex.split("gitlab-ci/tools/docker-run bazel build //ic-os/guestos:upload_guestos"), cwd=ic_root
    )
    version = None
    url = None
    with open(os.path.join(ic_root, "bazel-bin/ic-os/guestos/upload_guestos.urls")) as f:
        for line in f.readlines():
            print(line)
            m = re.match(r"http://download.dfinity.systems/ic/([0-9a-z\-]+)/ic-os/guestos/disk.img.tar.zstd", line)
            if m:
                url = line.strip()
                print(f"Found match: {version} for {url}")

    version = open(os.path.join(ic_root, "bazel-bin/ic-os/guestos/version.txt"), "r").read().strip()

    sha256 = subprocess.check_output(f"curl -L -s {url} | sha256sum", shell=True).decode().split()[0]
    print(f"sha256sum is [{sha256}]")
    return (version, url, sha256)


def deploy_farm(farm_instance, url, sha256sum, install_nns=False):
    print(f"Deploying Farm from URL: {url} ")
    farm_instance.create_farm_group()
    farm_instance.setup_disk_image(url, sha256sum)
    farm_instance.prepare_and_register_config_image()
    farm_instance.start_vm()
    if not farm_instance.wait_replica_up():
        print("Warning: Could not verify that IC replica is up, continuing anyway  .. ")

    ic_ip = farm_instance.ipv6[0][0]
    ic_url = f"http://[{ic_ip}]:8080"
    if install_nns:
        FLAGS.install_nns_bin = "../artifacts/release/ic-nns-init"
        FLAGS.nns_canisters = "../artifacts/canisters"
        ictools.wait_http_up(ic_url)
        nns_install = ictools.nns_install(farm_instance.ic_config, ic_url)
        if nns_install.returncode != 0:
            print("Installing the NNS fails, sleeping for 1h to allow debugging.")
            time.sleep(3600)
    return ic_ip


def main(argv):
    argv = FLAGS(argv)
    t_start = time.time()
    version, download_url, sha256sum = build_icos()
    duration_build = time.time() - t_start
    print(f"Duration for building: {duration_build}")

    misc.load_artifacts("../artifacts/release")

    # Basically the suite will pick the first application subnetwork to target.
    target_instance = farm.Farm("../artifacts/release", [1, 1], version)
    wg_instance = farm.Farm("../artifacts/release", [1], version)

    try:
        # We should really deploy those concurrently.
        target_ip = deploy_farm(target_instance, download_url, sha256sum, install_nns=True)
        wg_ip = deploy_farm(wg_instance, download_url, sha256sum)
        print(
            (
                f"IC url to use is: --targets={target_instance.ipv6[1][0]} --workload_generator_machines={wg_ip} "
                f"--testnet=none --wg_testnet=none --no_prometheus=True --no_instrument=True "
                f"--nns_url=http://[{target_ip}]:8080"
            )
        )

        duration = time.time() - t_start
        print(f"Deployment finished at: {duration}s")
        print("Sleeping for 1h. CTRL+C to terminate immediately")
        time.sleep(3600)

    finally:
        target_instance.delete_farm_group()
        wg_instance.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
