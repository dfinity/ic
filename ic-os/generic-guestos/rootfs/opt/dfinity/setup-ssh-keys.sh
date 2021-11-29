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

if [ ! -e /etc/ssh/ssh_host*key ]; then
    # XXX in order to have read-only root, this should be diverted
    # to /var using symbolic links
    cp /boot/config/ssh/* /etc/ssh/
fi
