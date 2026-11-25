#!/bin/bash

# Set up the SSH host keys and bind-mount them over /etc/ssh. The keys are
# generated on first boot and persisted:
#
# - Without TEE, in the "config" partition, so that they are stable across
#   upgrades.
# - With TEE (SEV-SNP), the host can read and write the "config" partition, so
#   the keys must never be stored there nor read from there. They are kept in
#   the SEV-encrypted store partition instead, which is carried across
#   upgrades. The Upgrade VM does not open the store and uses ephemeral keys.
#
# Only the host key files are installed into /etc/ssh, nothing else from the
# key directory (such as an sshd_config).

set -e

source /opt/ic/bin/config.sh
source /opt/ic/bin/key-dir.sh

KEY_FILES=(
    ssh_host_rsa_key
    ssh_host_rsa_key.pub
    ssh_host_ecdsa_key
    ssh_host_ecdsa_key.pub
    ssh_host_ed25519_key
    ssh_host_ed25519_key.pub
)

# Generates the host keys into the current directory.
generate_keys() {
    local GEN_DIR
    GEN_DIR=$(mktemp -d)
    mkdir -p "${GEN_DIR}"/etc/ssh
    ssh-keygen -A -f "${GEN_DIR}"
    for FILE in "${KEY_FILES[@]}"; do
        cp "${GEN_DIR}/etc/ssh/${FILE}" .
    done
    rm -rf "${GEN_DIR}"
}

cp -ar /etc/ssh/* /run/ic-node/etc/ssh/

# TEE_ENABLED is set by the 90-sev-status.sh environment generator. Anything
# other than 0 takes the TEE path, so that a missing value fails closed.
if [ "${TEE_ENABLED}" = 0 ]; then
    KEY_DIR=/boot/config/ssh
    if [ ! -e "${KEY_DIR}" ]; then
        create_key_dir "${KEY_DIR}" generate_keys
    fi
    for FILE in "${KEY_FILES[@]}"; do
        if [ -f "${KEY_DIR}/${FILE}" ]; then
            cp --remove-destination "${KEY_DIR}/${FILE}" /run/ic-node/etc/ssh/
        fi
    done
else
    if is_upgrade_vm; then
        # The Upgrade VM does not open the store.
        KEY_DIR=/run/ic-node/ssh_host_keys
    else
        KEY_DIR=/var/lib/ic/data/ssh_host_keys
        # Earlier versions stored the keys in the "config" partition, where the
        # host could read them, so they must be considered compromised. Remove
        # them only here, in the default VM: the Upgrade VM shares the "config"
        # partition with the running GuestOS.
        rm -rf /boot/config/ssh
    fi
    if ! copy_from_trusted_key_dir "${KEY_DIR}" /run/ic-node/etc/ssh "${KEY_FILES[@]}"; then
        create_key_dir "${KEY_DIR}" generate_keys
        restorecon -r "${KEY_DIR}"
        copy_from_trusted_key_dir "${KEY_DIR}" /run/ic-node/etc/ssh "${KEY_FILES[@]}"
    fi
fi

mount --bind /run/ic-node/etc/ssh /etc/ssh
# Fix security labels
restorecon -v -r /etc/ssh
