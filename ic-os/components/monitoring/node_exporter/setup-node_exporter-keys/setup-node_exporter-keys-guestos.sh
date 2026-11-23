#!/bin/bash

# Set up the node_exporter TLS key pair and bind-mount it over
# /etc/node_exporter. The key pair is generated on first boot and persisted:
#
# - Without TEE, in the "config" partition, so that it is stable across
#   upgrades.
# - With TEE (SEV-SNP), the host can read and write the "config" partition, so
#   the key pair must never be stored there nor read from there. It is kept in
#   the SEV-encrypted store partition instead, which is carried across
#   upgrades. The upgrade VM does not open the store and uses an ephemeral key
#   pair.

set -e

# TEE_ENABLED is set by the 90-sev-status.sh environment generator. Anything
# other than 0 takes the TEE path, so that a missing value fails closed.
if [ "${TEE_ENABLED}" = 0 ]; then
    KEY_DIR=/boot/config/node_exporter
else
    # Earlier versions stored the key pair in the "config" partition, where
    # the host could read it. It must be considered compromised.
    rm -rf /boot/config/node_exporter
    if mountpoint -q /var/lib/ic/data; then
        KEY_DIR=/var/lib/ic/data/node_exporter_tls
    else
        KEY_DIR=/run/ic-node/node_exporter_tls
    fi
fi

if [ ! -e "${KEY_DIR}" ]; then
    TMPDIR="$(mktemp -d)"
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout "${TMPDIR}/node_exporter.key" -out "${TMPDIR}/node_exporter.crt" -subj '/C=CH/ST=Zurich/L=Zurich/O=DFINITY Stiftung/OU=PfOps/CN=localhost' -addext 'subjectAltName = DNS:localhost'
    # Stage the key pair next to its final location and move it into place
    # atomically, so that an interrupted first boot leaves no partial key pair.
    rm -rf "${KEY_DIR}.new"
    mkdir -m 0700 "${KEY_DIR}.new"
    cp "${TMPDIR}/node_exporter.crt" "${TMPDIR}/node_exporter.key" "${KEY_DIR}.new/"
    sync "${KEY_DIR}.new"/* "${KEY_DIR}.new"
    mv "${KEY_DIR}.new" "${KEY_DIR}"
    rm -rf "${TMPDIR}"
fi

if [ "${TEE_ENABLED}" != 0 ]; then
    # Re-assert ownership and permissions on every boot, e.g.
    # upgrade-shared-data-store.sh may chown /var/lib/ic/data recursively.
    chown -R root:root "${KEY_DIR}"
    chmod 0700 "${KEY_DIR}"
    chmod 0600 "${KEY_DIR}/node_exporter.key"
fi

cp -ar /etc/node_exporter/* /run/ic-node/etc/node_exporter/
# Only install the key pair, nothing else from the key directory.
cp "${KEY_DIR}/node_exporter.crt" "${KEY_DIR}/node_exporter.key" /run/ic-node/etc/node_exporter/
chown root:root /run/ic-node/etc/node_exporter/node_exporter.crt
chmod 0644 /run/ic-node/etc/node_exporter/node_exporter.crt
chown root:node_exporter /run/ic-node/etc/node_exporter/node_exporter.key
chmod 0640 /run/ic-node/etc/node_exporter/node_exporter.key
mount --bind /run/ic-node/etc/node_exporter /etc/node_exporter
restorecon -v -r /etc/node_exporter
