#!/bin/bash

# Set up the SSH host keys and bind-mount them over /etc/ssh. The keys are
# generated on first boot and persisted:
#
# - Without TEE, in the "config" partition, so that they are stable across
#   upgrades.
# - With TEE (SEV-SNP), the host can read and write the "config" partition, so
#   the keys must never be stored there nor read from there. They are kept in
#   the SEV-encrypted store partition instead, which is carried across
#   upgrades. The upgrade VM does not open the store and uses ephemeral keys.
#
# Only the host key files are installed into /etc/ssh, nothing else from the
# key directory (such as an sshd_config).

set -e

KEY_FILES=(
    ssh_host_rsa_key
    ssh_host_rsa_key.pub
    ssh_host_ecdsa_key
    ssh_host_ecdsa_key.pub
    ssh_host_ed25519_key
    ssh_host_ed25519_key.pub
)

# TEE_ENABLED is set by the 90-sev-status.sh environment generator. Anything
# other than 0 takes the TEE path, so that a missing value fails closed.
if [ "${TEE_ENABLED}" = 0 ]; then
    KEY_DIR=/boot/config/ssh
else
    # Earlier versions stored the keys in the "config" partition, where the
    # host could read them. They must be considered compromised.
    rm -rf /boot/config/ssh
    if mountpoint -q /var/lib/ic/data; then
        KEY_DIR=/var/lib/ic/data/ssh_host_keys
    else
        KEY_DIR=/run/ic-node/ssh_host_keys
    fi
fi

if [ ! -e "${KEY_DIR}" ]; then
    TMPDIR=$(mktemp -d)
    mkdir -p "${TMPDIR}"/etc/ssh
    ssh-keygen -A -f "${TMPDIR}"
    # Stage the keys next to their final location and move them into place
    # atomically, so that an interrupted first boot leaves no partial key set.
    rm -rf "${KEY_DIR}.new"
    mkdir -m 0700 "${KEY_DIR}.new"
    for FILE in "${KEY_FILES[@]}"; do
        cp "${TMPDIR}/etc/ssh/${FILE}" "${KEY_DIR}.new/"
    done
    sync "${KEY_DIR}.new"/* "${KEY_DIR}.new"
    mv "${KEY_DIR}.new" "${KEY_DIR}"
    rm -rf "${TMPDIR}"
fi

if [ "${TEE_ENABLED}" != 0 ]; then
    # Re-assert ownership, permissions and labels on every boot, e.g.
    # upgrade-shared-data-store.sh may chown /var/lib/ic/data recursively.
    chown -R root:root "${KEY_DIR}"
    chmod 0700 "${KEY_DIR}"
    chmod 0600 "${KEY_DIR}"/ssh_host_*_key
    restorecon -r "${KEY_DIR}"
fi

cp -ar /etc/ssh/* /run/ic-node/etc/ssh/
for FILE in "${KEY_FILES[@]}"; do
    if [ -f "${KEY_DIR}/${FILE}" ]; then
        cp "${KEY_DIR}/${FILE}" /run/ic-node/etc/ssh/
    fi
done
mount --bind /run/ic-node/etc/ssh /etc/ssh
# Fix security labels
restorecon -v -r /etc/ssh
