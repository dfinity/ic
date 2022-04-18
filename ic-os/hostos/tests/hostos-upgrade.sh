#!/usr/bin/env bash
#
# Runs a Host OS upgrade from base version to new version
#
: <<'DOC'
tag::catalog[]

Title:: HostOS upgrade test

Parameters::
. ci_project_dir - the directory of the IC repository being checked out at.

Success::
. Testnet upgraded successfully and performs healthy after the upgrade.

end::catalog[]
DOC

set -e

if (($# < 1)); then
    echo >&2 "Usage: hostos-upgrade.sh <ci_project_dir>\n
    Example #1: hostos-upgrade.sh \"/builds/git/JgGsR4vA/4/dfinity-lab/public/ic\"
    Example #2: hostos-upgrade.sh \"/builds/git/JgGsR4vA/4/dfinity-lab/public/ic\" "
    exit 1
fi

ci_project_dir="$1"

# Make sure the host has mounted necessary devices into the docker container.
# And check dependencies.
ls -lah /dev/kvm /dev/net/tun

mkdir -p gitlab-runner-tmp
cd gitlab-runner-tmp

ls "${ci_project_dir}/ic-os/hostos/build-out/disk-img/host-disk-img.tar.gz"
ls "${ci_project_dir}/ic-os/hostos/build-out/update-img/host-update-img.tar.gz"
stat "${ci_project_dir}/ic-os/hostos/build-out/disk-img/host-disk-img.tar.gz"
tar --sparse -xvf "${ci_project_dir}/ic-os/hostos/build-out/disk-img/host-disk-img.tar.gz"

ls -lah

# Prepare network. There are more convenient ways to do it if requisite
# services are set up (which they aren't in a simple docker runner),
# but probably also helpful for debugging to have this "explicit" for now.

sudo ip link del ipv6_ic_node0 || true
sudo ip link del ipv6_ic_node1 || true
sudo ip link del ipv6_ic || true

sudo ip tuntap add ipv6_ic_node0 mode tap user ubuntu
sudo ip link set dev ipv6_ic_node0 up

sudo ip tuntap add ipv6_ic_node1 mode tap user ubuntu
sudo ip link set dev ipv6_ic_node1 up

sudo ip link add name ipv6_ic type bridge
sudo ip link set ipv6_ic_node0 master ipv6_ic
sudo ip link set ipv6_ic_node1 master ipv6_ic
sudo ip link set dev ipv6_ic up

sudo ip addr add fd00:2:1:1:1::1/64 dev ipv6_ic

HOSTOS_IMG="$(pwd)/disk.img"
UPGRADE_IMG="${ci_project_dir}/ic-os/hostos/build-out/update-img/host-update-img.tar.gz"
echo "Initial HostOS image: ${HOSTOS_IMG}"
echo "Upgrade HostOS image: ${UPGRADE_IMG}"

mkdir -p "${ci_project_dir}/ic-os/hostos/test-out/$out_dir"

# Actual test script, sets up VMs and drives the test.
"${ci_project_dir}/ic-os/hostos/tests/hostos-upgrade.py" \
    --vmtoolscfg=internal \
    --disk_image "${HOSTOS_IMG}" \
    --upgrade_tar "${UPGRADE_IMG}" \
    --log_directory "${ci_project_dir}/ic-os/hostos/test-out/$out_dir" \
    --timeout "$E2E_TEST_TIMEOUT"
