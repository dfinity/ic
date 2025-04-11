#!/bin/bash

set -ex

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "hostname") hostname="${value}" ;;
        esac
    done <"$1"
}

if [ -e /boot/config/network.conf ]; then
    cat /boot/config/network.conf
    read_variables /boot/config/network.conf
    hostname="${hostname:-blank}"
else
    hostname="unnamed"
fi

echo "${hostname}" >/run/ic-node/etc/hostname
mount --bind /run/ic-node/etc/hostname /etc/hostname
restorecon -v /etc/hostname
hostname "${hostname}"
