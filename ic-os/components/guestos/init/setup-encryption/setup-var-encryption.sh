#!/bin/bash

set -e

function transfer_log_state() {
    # The mountpoint of the freshly-created /var to copy the old logs into.
    local var_new="$1"

    # Obtain machine ID, as it will identify which log files to copy.
    # If machine ID is missing, something is very wrong -- but deal with
    # it gracefully by allowing the machine to continue booting anyways.
    MACHINE_ID=$(cat /etc/machine-id || echo invalid)
    echo "Successfully mounted old /var partition, copying contents for machine id: ${MACHINE_ID}"

    # First, copy latest journal files.
    mkdir -p "${var_new}/log/journal/${MACHINE_ID}"
    if cp -pv $(ls -t /mnt/var_old/log/journal/"${MACHINE_ID}"/*.journal | head -3) "${var_new}/log/journal/${MACHINE_ID}/"; then
        chown -R root.systemd-journal "${var_new}/log/journal/"
        chcon -R system_u:object_r:systemd_journal_t:s0 "${var_new}/log/journal/${MACHINE_ID}"
        ls -lZ "${var_new}/log/journal/${MACHINE_ID}"
    else
        echo "Failed to copy previous journal files"
    fi
}

VAR_PARTITION="$1"
OLD_VAR_PARTITION="$2"

echo "Setting up ${VAR_PARTITION} for use as encrypted /var."

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${VAR_PARTITION}")

# cf. the upgrade logic in "manageboot.sh": The target partition is wiped
# clean as part of the upgrade procedure. We can therefore really rely
# on having a clean slate here after first boot of an upgrade.
if [ "${TYPE}" == "crypto_LUKS" ]; then
    echo "Found LUKS header in partition ${VAR_PARTITION} for /var."
    /opt/ic/bin/guest_disk crypt-open var "$VAR_PARTITION"
else
    echo "No LUKS header found in partition ${VAR_PARTITION} for /var. Setting it up on first boot."
    /opt/ic/bin/guest_disk crypt-format var "$VAR_PARTITION"
    /opt/ic/bin/guest_disk crypt-open var "$VAR_PARTITION"
    echo "Populating /var filesystem in ${VAR_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/var_crypt -d /var
    # Fix root inode (mkfs fails to set correct security context).
    echo "ea_set / security.selinux system_u:object_r:var_t:s0\\000" | debugfs -w /dev/mapper/var_crypt

    # TODO(NODE-1655): This won't work anymore if SEV is enabled on the node and should be removed.
    echo "Attempting to save logs from previous system instance at ${OLD_VAR_PARTITION}"
    # Try to open the old encrypted /var partition, but allow for failure.
    if cryptsetup luksOpen "${OLD_VAR_PARTITION}" old_var_crypt --key-file /boot/config/store.keyfile; then
        echo "Successfully opened old /var partition"
        # Try to mount the filesystem, but allow for failure.
        if mount -o ro,context=system_u:object_r:var_t:s0 /dev/mapper/old_var_crypt /mnt/var_old; then
            echo "Successfully mounted old /var partition"
            # Mount the newly created filesystem so we can copy the previous
            # boot's logs into it. There is a race with the fstab `var.mount`
            # unit, which mounts /dev/mapper/var_crypt at /var: if it wins the
            # race, mounting the same device again at /mnt/var_new fails with
            # "already mounted or mount point busy". As this script runs under
            # `set -e`, a bare `mount` would then abort the script and skip the
            # log transfer (losing e.g. the orchestrator's graceful-shutdown
            # message from the previous boot). So mount it ourselves when we can,
            # and otherwise copy into the location where it is already mounted.
            var_new=""
            var_new_mounted_by_us=0
            if mount /dev/mapper/var_crypt /mnt/var_new; then
                var_new=/mnt/var_new
                var_new_mounted_by_us=1
            elif awk '$2 == "/var" { found = 1 } END { exit !found }' /proc/mounts; then
                # The fstab `var.mount` unit won the race and already mounted
                # var_crypt at /var (the only mountpoint it uses), so copy the
                # logs into that mount instead.
                var_new=/var
                echo "New /var is already mounted at /var; transferring logs there"
            else
                echo "Could not access the new /var filesystem; skipping log transfer"
            fi

            if [ -n "${var_new}" ] && ! transfer_log_state "${var_new}"; then
                # We should never reach this code, all possible errors during
                # log copying should have been handled inside the
                # transfor_log_state function. Previous log messages should
                # at least tell what is wrong.
                #
                # This check and code block exists only as a last safeguard to
                # ensure that the system continues booting no matter what.
                echo "Uncaught error transferring log state, but continuing boot"
            fi

            # Need to dispose of the mount we created (if any). This should never
            # fail, but just be safe and proceed in case of failure. It will
            # result in stale mountpoints at runtime which is silly but not fatal.
            if [ "${var_new_mounted_by_us}" = 1 ]; then
                umount /mnt/var_new || echo "Failed to unmount new /var in temporary location"
            fi
            umount /mnt/var_old || echo "Failed to unmount old /var in temporary location"
        fi
        # Need to close the old encrypted /var partition, but allow for failure.
        # If it fails, then we will simply have a crypto partition open that
        # we will not use. Additionally, we will at some point (during a later
        # upgrade) wipe the partition which is bad as it destroys all existing
        # cryptographic keys, but the kernel should still be able to manage
        # and continue operating.
        cryptsetup luksClose old_var_crypt || echo "Failed to close old /var crypto partition"
    fi
fi
