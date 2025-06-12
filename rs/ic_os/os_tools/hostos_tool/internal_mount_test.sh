#!/bin/bash
# Exit on any error
set -e

# 1. Verify we are running as root inside the sandbox
#if [[ "$(id -u)" -ne 0 ]]; then
#  echo "Error: Test is not running as root. Did you forget tags = ['requires-fakeroot']?"
#  exit 1
#fi
echo "Running as UID $(id -u). Privileges appear correct."

DISK_IMG_PATH="/home/ubuntu/.cache/bazel/_bazel_ubuntu/6d065581cce7ad9076e3b8db2b3afaf0/execroot/_main/bazel-out/k8-opt/bin/ic-os/guestos/envs/prod/disk.img"
MOUNT_POINT=$(mktemp -d)

echo "Attempting to loop mount with strace..."

echo "$DISK_IMG_PATH"
#/usr/sbin/losetup -f  "${TEST_TMPDIR}/disk.img"
dd skip=206848 count=204800 bs=512 if=$DISK_IMG_PATH of="${TEST_TMPDIR}/partition.img"
mkdir "${TEST_TMPDIR}/partition"
#fuse2fs "${TEST_TMPDIR}/partition.img" "${TEST_TMPDIR}/partition"
#echo "rdump / ${TEST_TMPDIR}/partition" | /usr/sbin/debugfs "${TEST_TMPDIR}/partition.img"
mcopy -s -n -i "${TEST_TMPDIR}/partition.img" ::* "${TEST_TMPDIR}/partition"
ls ${TEST_TMPDIR}/partition
exit 1
# EXECUTE with strace
# The -f flag follows forks, which mount might do.
# The -o flag writes output to a file.
mount -v -o offset=206848 "$DISK_IMG_PATH" "$MOUNT_POINT"

echo "Mount command finished."

# 4. Verify the mount exists and is usable
#    'grep' will return a non-zero exit code if the mount isn't found,
#    which 'set -e' will catch.
grep "$MOUNT_POINT" /proc/mounts
echo "Verified mount in /proc/mounts."

#    Now, use the mount.
echo "Creating a file on the new tmpfs mount..."
echo "hello from tmpfs" > "$MOUNT_POINT/my_test_file.txt"
cat "$MOUNT_POINT/my_test_file.txt"

# 5. Clean up (good practice, though the sandbox will be destroyed anyway)
echo "Unmounting the filesystem..."
umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

echo "Test complete. Successfully created, used, and cleaned up a temporary mount."
exit 0
