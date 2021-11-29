#!/usr/bin/env bash

# Takes a filesystem tree, optionally applies selinux labels (as
# configured in file contexts), and turns it into two filesystem images:
# one for the "boot" directory, and one for the "root".
#
# This needs to be done in a single step such that this can all be run
# under a single "fakeroot" invocation -- it appears that fakeroot has
# a bug that it does not preserve extended attributes across sessions.

set -e

BASEDIR="$1"
ROOT_IMAGE="$2"
BOOT_IMAGE="$3"

# This is only relevant if SELinux is used inside the target system --
# label all files correctly in this case.
FILE_CONTEXTS="${BASEDIR}/etc/selinux/default/contexts/files/file_contexts"

if [ -e "${FILE_CONTEXTS}" ]; then
    TMPDIR=$(mktemp -d)
    trap "rm -rf ${TMPDIR}" exit
    ROOT_FILE_CONTEXTS="${TMPDIR}/root_file_contexts"
    BOOT_FILE_CONTEXTS="${TMPDIR}/boot_file_contexts"
    sed -e '/<<none>>/d' -e 's!^/!!' <"${FILE_CONTEXTS}" >"${ROOT_FILE_CONTEXTS}"
    sed -e '/<<none>>/d' -e 's!^/boot/!!' -e t -e d <"${FILE_CONTEXTS}" >"${BOOT_FILE_CONTEXTS}"
fi

BOOT_SIZE=$(stat --print=%s "${BOOT_IMAGE}")
ROOT_SIZE=$(stat --print=%s "${ROOT_IMAGE}")

if [ "${BOOT_FILE_CONTEXTS}" != "" ]; then
    make_ext4fs -T 0 -l "${BOOT_SIZE}" -S "${BOOT_FILE_CONTEXTS}" "${BOOT_IMAGE}" "${BASEDIR}/boot"
else
    make_ext4fs -T 0 -l "${BOOT_SIZE}" "${BOOT_IMAGE}" "${BASEDIR}/boot"
fi

# Delete the contents of /boot/ -- boot partition will be mounted
# on top of this directory. We don't want its contents in the root
# image.
rm -rf "${BASEDIR}"/boot/*

if [ "${ROOT_FILE_CONTEXTS}" != "" ]; then
    make_ext4fs -T 0 -l "${ROOT_SIZE}" -S "${ROOT_FILE_CONTEXTS}" "${ROOT_IMAGE}" "${BASEDIR}"
else
    make_ext4fs -T 0 -l "${ROOT_SIZE}" "${ROOT_IMAGE}" "${BASEDIR}"
fi

# make_ext4fs has the defect that it does not preserve file ownership of
# input files when creating the FS image. Luckily, we do not have many files
# in this category. Identify all files, and fix them up in the file system
# image after build.

# Find all files that are not owned root:root.
for FIXUP_FILE in $(find "${BASEDIR}" -uid +0 -o -gid +0); do
    # Get ownership of file.
    FILE_UID=$(stat --format "%u" ${FIXUP_FILE})
    FILE_GID=$(stat --format "%g" ${FIXUP_FILE})
    # Strip prefix to get correct target file.
    TARGET_FILE="${FIXUP_FILE#"${BASEDIR}/"}"
    # Apply ownership changes.
    echo "Fix ownership of ${TARGET_FILE} to ${FILE_UID}:${FILE_GID}"
    echo -e "\n${FILE_UID}\n${FILE_GID}\n" | debugfs -w "${ROOT_IMAGE}" -R "modify_inode ${TARGET_FILE}" >/dev/null 2>&1
done
