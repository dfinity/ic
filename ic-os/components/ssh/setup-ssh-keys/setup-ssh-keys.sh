#!/bin/bash

# If no ssh keys exist, copy them from "config" partition over to our
# system. Create them in "config" partition as needed.

set -e

if [ ! -e /boot/config/ssh ]; then
    TMPDIR=$(mktemp -d)
    mkdir -p "${TMPDIR}"/etc/ssh
    ssh-keygen -A -f "${TMPDIR}"
    mkdir /boot/config/ssh
    cp "${TMPDIR}"/etc/ssh/ssh_host* /boot/config/ssh
    rm -rf "${TMPDIR}"
fi

cp -ar /etc/ssh/* /run/ic-node/etc/ssh/
cp /boot/config/ssh/* /run/ic-node/etc/ssh/
mount --bind /run/ic-node/etc/ssh /etc/ssh
# Fix security labels
restorecon -v -r /etc/ssh
