#!/usr/bin/env bash

# Simple wrapper around icos_deploy.sh to do a deployment on local virtual machines
#
# Before running for the first time, make sure you have all the dependencies:
# sudo apt install ansible jq rclone
#
# Before running
# 0. You can compile the replica locally
# 1. make sure you have testnet/env/localhost defined.
# 2. icos_deploy.sh has been modified to copy canisters and binaries from local
# compilation
# 3. Can ansible to the localhost using the usename logged in
#    3.1. you should be able to ssh $USER@localhost
#    3.2. sudo ls   # without using a password
#
# 4. You are able to run VMs on you local machine.
#    You have defined a VLAN66 "virtual network" with the following XML config
#
# <network connections="6">
#  <name>vlan66</name>
#  <uuid>5a97d3e3-0357-4ada-8b7f-d4e0c298c9ee</uuid>
#  <forward mode="nat">
#    <nat>
#      <port start="1024" end="65535"/>
#    </nat>
#  </forward>
#  <bridge name="virbr1" stp="on" delay="0"/>
#  <mac address="52:54:00:4a:83:98"/>
#  <domain name="vlan66"/>
#  <ip address="192.168.100.1" netmask="255.255.255.0">
#    <dhcp>
#      <range start="192.168.100.128" end="192.168.100.254"/>
#    </dhcp>
#  </ip>
#  <ip family="ipv6" address="2a00:fb01:400:42::65" prefix="64">
#  </ip>
#  </network>


set -eEuo pipefail

virsh net-info vlan66
retval=$?
if [ $retval -ne 0 ]; then
       echo "vlan66 not configured"
       return -1
fi

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
${REPO_ROOT}/gitlab-ci/container/build-ic.sh -i -b -c
bash -x ${REPO_ROOT}/testnet/tools/icos_deploy.sh localhost --deploy-local --git-revision $(${REPO_ROOT}/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh master)
