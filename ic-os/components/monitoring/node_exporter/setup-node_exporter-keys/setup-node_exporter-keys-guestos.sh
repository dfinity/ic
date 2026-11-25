#!/bin/bash

# Set up the node_exporter TLS key pair and bind-mount it over
# /etc/node_exporter. The key pair is generated on first boot and persisted:
#
# - Without TEE, in the "config" partition, so that it is stable across
#   upgrades.
# - With TEE (SEV-SNP), the host can read and write the "config" partition, so
#   the key pair must never be stored there nor read from there. It is kept in
#   the SEV-encrypted store partition instead, which is carried across
#   upgrades. The Upgrade VM does not open the store and uses an ephemeral key
#   pair.

set -e

source /opt/ic/bin/config.sh
source /opt/ic/bin/key-dir.sh

KEY_FILES=(
    node_exporter.crt
    node_exporter.key
)

# Generates the key pair into the current directory.
generate_keys() {
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout node_exporter.key -out node_exporter.crt -subj '/C=CH/ST=Zurich/L=Zurich/O=DFINITY Stiftung/OU=PfOps/CN=localhost' -addext 'subjectAltName = DNS:localhost'
}

cp -ar /etc/node_exporter/* /run/ic-node/etc/node_exporter/

# TEE_ENABLED is set by the 90-sev-status.sh environment generator. Anything
# other than 0 takes the TEE path, so that a missing value fails closed.
if [ "${TEE_ENABLED}" = 0 ]; then
    KEY_DIR=/boot/config/node_exporter
    if [ ! -e "${KEY_DIR}" ]; then
        create_key_dir "${KEY_DIR}" generate_keys
    fi
    # Only install the key pair, nothing else from the key directory.
    # --remove-destination: create new files with the source's mode, rather
    # than writing into the world-readable placeholders copied above.
    for FILE in "${KEY_FILES[@]}"; do
        cp --remove-destination "${KEY_DIR}/${FILE}" /run/ic-node/etc/node_exporter/
    done
else
    if is_upgrade_vm; then
        # The Upgrade VM does not open the store.
        KEY_DIR=/run/ic-node/node_exporter_tls
    else
        KEY_DIR=/var/lib/ic/data/node_exporter_tls
        # Earlier versions stored the key pair in the "config" partition, where
        # the host could read it, so it must be considered compromised. Remove
        # it only here, in the default VM: the Upgrade VM shares the "config"
        # partition with the running GuestOS.
        rm -rf /boot/config/node_exporter
    fi
    if ! copy_from_trusted_key_dir "${KEY_DIR}" /run/ic-node/etc/node_exporter "${KEY_FILES[@]}"; then
        create_key_dir "${KEY_DIR}" generate_keys
        copy_from_trusted_key_dir "${KEY_DIR}" /run/ic-node/etc/node_exporter "${KEY_FILES[@]}"
    fi
fi

chown root:root /run/ic-node/etc/node_exporter/node_exporter.crt
chmod 0644 /run/ic-node/etc/node_exporter/node_exporter.crt
chown root:node_exporter /run/ic-node/etc/node_exporter/node_exporter.key
chmod 0640 /run/ic-node/etc/node_exporter/node_exporter.key
mount --bind /run/ic-node/etc/node_exporter /etc/node_exporter
restorecon -v -r /etc/node_exporter
