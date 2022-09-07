#!/usr/bin/python3
import getpass
import os
import sys
import time

import gflags
import requests
from tests import ictools

FLAGS = gflags.FLAGS


def main(argv):
    argv = FLAGS(argv)

    version = open("ic-os/guestos/version.txt.wrapped", "r").read().strip()

    img_hash = open("ic-os/guestos/disk.img.tar.zstd.sha256.wrapped", "r").read().strip()

    url = open("ic-os/guestos/upload_guestos_disk.img.tar.zstd.url", "r").read().split()[0]

    FLAGS.ic_prep_bin = "rs/prep/ic-prep"

    FARM_BASE_URL = "https://farm.dfinity.systems"
    TTL = 3600

    group_name = "testvm-" + getpass.getuser() + "-" + time.strftime("%Y-%M-%d-%H-%m-%S")
    group_url = FARM_BASE_URL + "/group/" + group_name

    print("Setting up farm group")
    # Delete old group (ignoring error)
    response = requests.delete(group_url)
    # Create group
    response = requests.post(
        group_url,
        json={"ttl": TTL, "spec": {"vmAllocation": "distributeWithinSingleHost"}},
        headers={"accept": "application/json"},
    )
    response.raise_for_status()
    expiry = response.json()["expiresAt"]
    print("Farm group expires at", expiry)

    print("Setting up VM using disk image %s" % url)
    # Set up VM using image uploaded previously
    primary_image = {"_tag": "icOsImageViaUrl", "url": url, "sha256": img_hash}
    vm_url = group_url + "/vm/main"

    response = requests.post(
        vm_url,
        json={
            "type": "production",
            "vCPUs": 2,
            "memoryKiB": 25165824,
            "primaryImage": primary_image,
            "primaryImageMinimalSizeGiB": 100,
        },
        headers={"accept": "application/json"},
    )
    response.raise_for_status()
    ipv6 = response.json()["ipv6"]

    print("Setting up config image")
    # Generate config image
    ic_config = ictools.ic_prep(
        subnets=[[ipv6]],
        version=version,
        root_subnet=0,
    )
    config_image = ictools.build_ic_prep_inject_config(ic_config, 0, ictools.build_ssh_extra_config())
    os.system("gzip " + config_image)
    response = requests.post(
        group_url + "/file",
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

    print("Starting VM")
    response = requests.put(vm_url + "/start")
    response.raise_for_status()

    print("Serial console at %s/console" % vm_url)
    print("Connect to system via ssh admin@%s" % ipv6)


if __name__ == "__main__":
    main(sys.argv)
