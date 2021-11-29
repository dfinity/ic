#!/bin/bash

set -e

# Set up file permissions for everything touched by replica. It is required in
# order to let other services read part (and only part!) of the data.
#
# This is run at boot to ensure that the on-disk state is set correctly,
# independently of how it was set previously. This ensures that state bits
# are also corrected after an upgrade.
#
# Ideally, it should actually only run once after initial install or an
# upgrade (as part of format conversion).

# Set up unix owner ids in target directory, recursively.
#
# Arguments:
# - $1: Target directory
# - $2: user to assign
# - $3: group to assign
function make_group_owned_and_sticky() {
    local TARGET_DIR="$1"
    local USER="$2"
    local GROUP="$3"

    mkdir -p "${TARGET_DIR}"
    chown -R "${USER}:${GROUP}" "${TARGET_DIR}"
    chmod u=rwX,g=rX,o= -R "${TARGET_DIR}"
    find "${TARGET_DIR}" -type d | xargs chmod g+s
}

make_group_owned_and_sticky /var/lib/ic/backup ic-replica backup
make_group_owned_and_sticky /var/lib/ic/crypto ic-replica confidential
make_group_owned_and_sticky /var/lib/ic/data/ic_consensus_pool ic-replica nonconfidential
make_group_owned_and_sticky /var/lib/ic/data/ic_state ic-replica nonconfidential
make_group_owned_and_sticky /var/lib/ic/data/ic_registry_local_store ic-replica nonconfidential

# Fix up security labels for everything.
echo "Restoring SELinux security contexts in /var/lib/ic"
restorecon -p -r /var/lib/ic/data /var/lib/ic/crypto

# Note: we are not setting up contexts individually for /var/lib/ic/backup.
# This is handled instead by mount option for the filesystem in its entirety.
