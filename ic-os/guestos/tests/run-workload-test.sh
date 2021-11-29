#!/usr/bin/env bash

set -euo pipefail

# Run the e2e (workload) test. This script is intended to be executed inside
# a docker/ubuntu gitlab runner. See Dockerfile and run-workload-test.sh
# for the environment expected by this script.

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")

# Prepare network. There are more convenient ways to do it if requisite
# services are set up (which they aren't in a simple docker runner),
# but probably also helpful for debugging to have this "explicit" for now.

ip tuntap add ipv6_ic_node0 mode tap
ip link set dev ipv6_ic_node0 up

ip tuntap add ipv6_ic_node1 mode tap
ip link set dev ipv6_ic_node1 up

ip link add name ipv6_ic type bridge
ip link set ipv6_ic_node0 master ipv6_ic
ip link set ipv6_ic_node1 master ipv6_ic
ip link set dev ipv6_ic up

# Actual test script, sets up VMs and drives the test.

"${BASE_DIR}"/e2e-workload.py \
    --disk_image /tmp/disk.img \
    --ic_prep_bin /usr/local/bin/ic-prep \
    --ic_workload_generator_bin /usr/local/bin/ic-workload-generator
