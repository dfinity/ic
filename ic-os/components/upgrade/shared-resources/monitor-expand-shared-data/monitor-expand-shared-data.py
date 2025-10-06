#!/usr/bin/python3
"""
Monitors the usage of /var/lib/ic/data and expands it if needed.

This script monitors available space on the filesystem and triggers expansion
if it drops below a certain threshold.

Expansion is performed by extending the underlying logical volume first, and
then performing an online resize operation on the target filesystem. Only xfs
is supported at present.
"""

import json
import os
import subprocess
import sys
import time

VG_NAME = "store"
LV_NAME = "shared-data"
MOUNT_POINT = "/var/lib/ic/data"
DEVICE_NAME = "/dev/" + VG_NAME + "/" + LV_NAME

# 15TiB in MiB
MAX_LV_SIZE = 15 * 1024 * 1024


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
            ["lvs", "--units", "k", "-o", "lv_size", "--reportformat", "json", "{0}/{1}".format(vg_name, lv_name)],
            stdout=subprocess.PIPE,
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
    st = os.statvfs(MOUNT_POINT)
    return st.f_bsize * st.f_bavail // 1048576


def expand_lv(device_name, lv_name, mount_point, fs_free, required_avail, expand_size):
    sys.stderr.write(
        "Free space on %s is %d MiB -- below %d MiB, expanding by %d MiB\n"
        % (device_name, fs_free, required_avail, expand_size)
    )
    sys.stderr.flush()

    # Extend the logical volume.
    subprocess.run(["lvextend", "-L", "+%dM" % expand_size, "%s/%s" % (VG_NAME, lv_name)], check=True)

    # Expand the filesystem to utilize the space that is now available
    # in the logical volume.
    subprocess.run(["xfs_growfs", mount_point], check=True)


def main():
    # Total VG and LV sizes change only if we call lvextend below.
    vg_size, vg_free = get_vg_size_and_free(VG_NAME)
    lv_size = get_lv_size(VG_NAME, LV_NAME)

    while True:
        # Cap the size of data to MAX_LV_SIZE
        available = MAX_LV_SIZE - lv_size

        # Only run if we have space to expand into.
        if available > 0 and vg_free > 0:
            fs_free = get_fsfree(MOUNT_POINT)

            # Consider the VG in "chunks" of 10%.
            required_chunk_size = int(vg_size * 0.10)

            #  If we have less than 1 "chunk" of free space...
            if fs_free < required_chunk_size:
                # ...expand by half a "chunk", or what space remains.
                expand_size = int(min(vg_size * 0.05, available, vg_free))
                expand_lv(DEVICE_NAME, LV_NAME, MOUNT_POINT, fs_free, required_chunk_size, expand_size)

                # Now the volume group available size changed, query it again.
                vg_size, vg_free = get_vg_size_and_free(VG_NAME)
                lv_size = get_lv_size(VG_NAME, LV_NAME)

        # In the inner loop we are really making just a single syscall
        # (statfs) that is also pretty cheap. So we can afford to do it fairly
        # frequently.
        time.sleep(1)


if __name__ == "__main__":
    main()
