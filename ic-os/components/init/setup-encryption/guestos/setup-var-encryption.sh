#!/bin/bash

set -e

function transfer_log_state() {
    # Obtain machine ID, as it will identify which log files to copy.
    # If machine ID is missing, something is very wrong -- but deal with
    # it gracefully by allowing the machine to continue booting anyways.
    MACHINE_ID=$(cat /etc/machine-id || echo invalid)
    echo "Successfully mounted old /var partition, copying contents for machine id: ${MACHINE_ID}"

    # First, copy actual journal files.
    if cp -vr /mnt/var_old/log/journal/"${MACHINE_ID}" /mnt/var_new/log/journal/"${MACHINE_ID}"; then
        chown -R root.systemd-journal /mnt/var_new/log/journal/"${MACHINE_ID}"
        chcon -R system_u:object_r:systemd_journal_t:s0 /mnt/var_new/log/journal/"${MACHINE_ID}"
        ls -lZ /mnt/var_new/log/journal/"${MACHINE_ID}"
    else
        echo "Failed to copy previous journal files"
    fi

    # Now, copy filebeat state files such that it resumes
    # shipping logs from correct place.
    for FILE in meta.json registry; do
        if [ -f "/mnt/var_old/lib/filebeat/${FILE}" ]; then
            if cp -v "/mnt/var_old/lib/filebeat/${FILE}" "/mnt/var_new/lib/filebeat/${FILE}"; then
                chown filebeat.filebeat "/mnt/var_new/lib/filebeat/${FILE}"
                chmod 600 "/mnt/var_new/lib/filebeat/${FILE}"
                chcon system_u:object_r:filebeat_var_lib_t:s0 "/mnt/var_new/lib/filebeat/${FILE}"
            else
                echo "Failed to copy filebeat state file: ${FILE}"
            fi
        else
            echo "Missing filebeat state file: ${FILE}"
        fi
    done
    ls -lZ "/mnt/var_new/lib/filebeat"
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
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file /boot/config/store.keyfile
else
    echo "No LUKS header found in partition ${VAR_PARTITION} for /var. Setting it up on first boot."
    # Set minimal iteration count -- we already use a random key with
    # maximal entropy, pbkdf doesn't gain anything (besides slowing
    # down boot by a couple seconds which needlessly annoys for testing).
    cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${VAR_PARTITION}" /boot/config/store.keyfile
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file /boot/config/store.keyfile
    echo "Populating /var filesystem in ${VAR_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/var_crypt -d /var
    # Fix root inode (mkfs fails to set correct security context).
    echo "ea_set / security.selinux system_u:object_r:var_t:s0\\000" | debugfs -w /dev/mapper/var_crypt

    echo "Attempting to save logs from previous system instance at ${OLD_VAR_PARTITION}"
    # Try to open the old encrypted /var partition, but allow for failure.
    if cryptsetup luksOpen "${OLD_VAR_PARTITION}" old_var_crypt --key-file /boot/config/store.keyfile; then
        echo "Successfully opened old /var partition"
        # Try to mount the filesystem, but allow for failure.
        if mount -o ro,context=system_u:object_r:var_t:s0 /dev/mapper/old_var_crypt /mnt/var_old; then
            echo "Successfully mounted old /var partition"
            # Mount newly created filesystem. This must never go wrong -- if it,
            # the new filesystem is destroyed and there is no point in
            # continuing. So, do not try to catch an error here.
            mount /dev/mapper/var_crypt /mnt/var_new
            if ! transfer_log_state; then
                # We should never reach this code, all possible errors during
                # log copying should have been handled inside the
                # transfor_log_state function. Previous log messages should
                # at least tell what is wrong.
                #
                # This check and code block exists only as a last safeguard to
                # ensure that the system continues booting no matter what.
                echo "Uncaught error transferring log state, but continuing boot"
            fi

            # Need to dispose of filesystem mounts. This should never fail,
            # but just be safe and proceed in case of failure. It will result
            # in stale mountpoints at runtime which is silly but not fatal.
            umount /mnt/var_new || echo "Failed to unmount new /var in temporary location"
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
