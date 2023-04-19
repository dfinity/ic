#!/usr/bin/python3
"""
Monitors the usage of /var/lib/ic/data and expands it if needed.

This script monitors available space on the filesystem and triggers expansion
if it drops below a certain threshold.

Expansion is performed by extending the underlying logical volume first, and
then performing an online resize operation on the target filesystem. Both
xfs and ext4 filesystems are supported by this script (even though only
xfs is used at present).
"""

import json
import os
import subprocess
import sys
import time

VG_NAME = "store"
DATA_LV_NAME = "shared-data"
DATA_MOUNT_POINT = "/var/lib/ic/data"
BACKUP_LV_NAME = "shared-backup"
BACKUP_MOUNT_POINT = "/var/lib/ic/backup"

DATA_DEVICE_NAME = "/dev/" + VG_NAME + "/" + DATA_LV_NAME
BACKUP_DEVICE_NAME = "/dev/" + VG_NAME + "/" + BACKUP_LV_NAME

REQUIRED_AVAIL_FRACTION = 0.10
EXPAND_FRACTION = 0.05


def get_vg_size_and_free(vg_name):
    """
    Obtains total size and free space in volume group.

    Sizes measured in MiB.
    """
    vgs_data = json.loads(
        subprocess.Popen(
            ["vgs", "--units", "k", "-o", "vg_size,vg_free", "--reportformat", "json", vg_name], stdout=subprocess.PIPE
        ).stdout.read()
    )
    # The json output of vgs looks roughly like this:
    #  {
    #      "report": [
    #          {
    #              "vg": [
    #                  {"vg_size":"498814976.00k", "vg_free":"116084736.00k"}
    #              ]
    #          }
    #      ]
    #  }
    #
    # When parsing, we need to strip the unit ("k") at the end of the outputs,
    # and also be careful to strip decimal places (which may or may not be
    # there).
    vg_size = int(vgs_data["report"][0]["vg"][0]["vg_size"][:-1].split(".")[0]) // 1024
    vg_free = int(vgs_data["report"][0]["vg"][0]["vg_free"][:-1].split(".")[0]) // 1024

    return vg_size, vg_free


def get_lv_size(vg_name, lv_name):
    """
    Obtains total size of logical volume.

    Sizes measured in MiB.
    """
    lvs_data = json.loads(
        subprocess.Popen(
            ["lvs", "--units", "k", "-o", "lv_free", "--reportformat", "json", "{0}/{1}".format(vg_name, lv_name)], stdout=subprocess.PIPE
        ).stdout.read()
    )
    # The json output of lvs looks roughly like this:
    #  {
    #      "report": [
    #          {
    #              "lv": [
    #                  {"lv_size":"116084736.00k"}
    #              ]
    #          }
    #      ]
    #  }
    #
    # When parsing, we need to strip the unit ("k") at the end of the outputs,
    # and also be careful to strip decimal places (which may or may not be
    # there).
    lv_size = int(lvs_data["report"][0]["lv"][0]["lv_size"][:-1].split(".")[0]) // 1024

    return lv_size


def get_fsfree(path):
    """
    Obtains available space in filesystem.

    Size measured in MiB.
    """
    st = os.statvfs(path)
    return st.f_bsize * st.f_bavail // 1048576


def get_fstype(blkdev):
    lines = subprocess.Popen(["blkid", "-o", "udev", blkdev], stdout=subprocess.PIPE).stdout.read().split(b"\n")
    kvs = [line.decode("utf-8").split("=") for line in lines if line]
    fields = {kv[0]: kv[1] for kv in kvs}
    return fields["ID_FS_TYPE"]


def expand_lv(device_name, lv_name, fs_type, mount_point, fs_free, required_avail, expand_size):
    sys.stderr.write(
        "Free space on %s is %d MiB -- below %d MiB, expanding by %d MiB\n"
        % (device_name, fs_free, required_avail, expand_size)
    )
    sys.stderr.flush()

    # Extend the logical volume.
    subprocess.run(["lvextend", "-L", "+%dM" % expand_size, "%s/%s" % (VG_NAME, lv_name)], check=True)

    # Expand the filesystem to utilize the space that is now available
    # in the logical volume.
    if fs_type == "xfs":
        grow_cmd = ["xfs_growfs", mount_point]
    elif fs_type == "ext4":
        grow_cmd = ["resize2fs", device_name]
    subprocess.run(grow_cmd, check=True)


def main():
    # File system type is not going to change, fetch only once.
    data_fs_type = get_fstype(DATA_DEVICE_NAME)
    backup_fs_type = get_fstype(BACKUP_DEVICE_NAME)

    # Total sizes changes only if we call lvextend below.
    vg_size, vg_free = get_vg_size_and_free(VG_NAME)
    data_size = get_lv_size(VG_NAME, DATA_LV_NAME)
    backup_size = get_lv_size(VG_NAME, BACKUP_LV_NAME)

    while True:
        data_fs_free = get_fsfree(DATA_MOUNT_POINT)
        backup_fs_free = get_fsfree(BACKUP_MOUNT_POINT)

        # Resize when there is less than 10% storage remaining free on the LV.
        data_required_avail = int(data_size * REQUIRED_AVAIL_FRACTION)
        backup_required_avail = int(backup_size * REQUIRED_AVAIL_FRACTION)
        # Expand by 5% of the VG, or to fill remaining free space, whichever is less.
        expand_size = int(min(vg_size * EXPAND_FRACTION, vg_free))

        # If we have space to expand into.
        if expand_size > 0:
            # Prioritize re-sizing data.
            if data_fs_free < data_required_avail:
                expand_lv(DATA_DEVICE_NAME, DATA_LV_NAME, data_fs_type, DATA_MOUNT_POINT, data_fs_free, data_required_avail, expand_size)

                # Now the volume group available size changed, query it again.
                vg_size, vg_free = get_vg_size_and_free(VG_NAME)
            elif backup_fs_free < backup_required_avail:
                expand_lv(BACKUP_DEVICE_NAME, BACKUP_LV_NAME, backup_fs_type, BACKUP_MOUNT_POINT, backup_fs_free, backup_required_avail, expand_size)

                # Now the volume group available size changed, query it again.
                vg_size, vg_free = get_vg_size_and_free(VG_NAME)

        # In the inner loop we are really making just a single syscall
        # (statfs) that is also pretty cheap. So we can afford to do it fairly
        # frequently.
        time.sleep(1)


if __name__ == "__main__":
    main()
