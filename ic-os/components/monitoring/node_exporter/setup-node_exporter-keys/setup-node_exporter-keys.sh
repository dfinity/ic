#!/bin/bash

# If no node_exporter TLS private key exist, copy from "config" partition over
# to our system. Create TLS key pair in "config" partition as needed.

set -e

if [ ! -e "/boot/config/node_exporter" ]; then
    TMPDIR="$(mktemp -d)"
    mkdir -p "${TMPDIR}"
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout "${TMPDIR}/node_exporter.key" -out "${TMPDIR}/node_exporter.crt" -subj '/C=CH/ST=Zurich/L=Zurich/O=DFINITY Stiftung/OU=PfOps/CN=localhost' -addext 'subjectAltName = DNS:localhost'
    mkdir -p /boot/config/node_exporter
    cp --archive ${TMPDIR}/node_exporter\.* /boot/config/node_exporter/
    rm -rf ${TMPDIR}
fi

cp -ar /etc/node_exporter/* /run/ic-node/etc/node_exporter/
cp /boot/config/node_exporter/node_exporter\.* /run/ic-node/etc/node_exporter
chown root:root /run/ic-node/etc/node_exporter/node_exporter.crt
chmod 0644 /run/ic-node/etc/node_exporter/node_exporter.crt
chown root:node_exporter /run/ic-node/etc/node_exporter/node_exporter.key
chmod 0640 /run/ic-node/etc/node_exporter/node_exporter.key
mount --bind /run/ic-node/etc/node_exporter /etc/node_exporter
restorecon -v -r /etc/node_exporter
