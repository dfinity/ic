#!/usr/bin/env python3
#
# Builds a lvm image from individual partition images and a volume
# table description. The actual lvm image is wrapped up into a tar file
# because the raw file is sparse.
#
# The input partition images are also expected to be given as tar files,
# where each tar archive must contain a single file named "partition.img".
#
# Call example:
#   build_lvm_image -v volumes.csv -o partition-hostlvm.tar part1.tar part2.tar ...
#
import argparse
import os
import subprocess
import sys
import tarfile
import tempfile

from reproducibility import get_tmpdir_checking_block_size
from reproducibility import print_artifact_info

LVM_HEADER_SIZE_BYTES = int(2048 * 512)
BYTES_PER_MEBIBYTE = int(2 ** 20)
EXTENT_SIZE_BYTES = int(4 * BYTES_PER_MEBIBYTE)


def read_volume_description(data):
    lvm_entries = []
    for line in data.split("\n"):
        if line.startswith("#") or not line:
            continue
        cols = tuple(s.strip() for s in line.split(","))
        lvm_entries.append(
            {
                "name": cols[0],
                "start": int(cols[1]),
                "size": int(cols[2]),
                "uuid": cols[3],
                "description": cols[4],
            }
        )
    return lvm_entries


def validate_volume_table(lvm_entries):
    """
    Validate volume table.

    Validate that volumes do not overlap.
    """
    end = 0
    for entry in lvm_entries:
        if entry["start"] < end:
            raise RuntimeError("Partition %s overlaps with previous" % entry["name"])
        end = entry["start"] + entry["size"]


def generate_lvm_structure(lvm_entries, vg_name, vg_uuid, pv_uuid, size):
    # Create the header
    lines = f"""
contents = "Text Format Volume Group"
version = 1

{vg_name} {{
id = "{vg_uuid}"
seqno = 1
format = "lvm2" # informational
status = ["RESIZEABLE", "READ", "WRITE"]
flags = []
extent_size = 8192 # 4 Mebibytes in 512 byte sectors
max_lv = 0
max_pv = 0
metadata_copies = 0
"""

    # Add section for PVs
    dev_size = int(size / 512)  # Sector size
    pe_count = int((size - LVM_HEADER_SIZE_BYTES) / EXTENT_SIZE_BYTES)

    lines += f"""
physical_volumes {{
pv0 {{
id = "{pv_uuid}"

status = ["ALLOCATABLE"]
flags = []
dev_size = {dev_size}
pe_start = 2048
pe_count = {pe_count}
}}
}}
"""

    # Add section for LVs
    #
    # ----------
    # Example:
    # ----------
    # logical_volumes {
    #   esp {
    #     id = "qxkWcA-0XF7-scev-KJ2F-T4hY-c9xH-6tuqZ7"
    #     status = ["READ", "WRITE", "VISIBLE"]
    #     flags = []
    #     creation_time = 1620345600
    #     creation_host = "builder"
    #     segment_count = 1
    #
    #     segment1 {
    #       start_extent = 0
    #       extent_count = 25
    #
    #       type = "striped"
    #       stripe_count = 1        # linear
    #
    #       stripes = [
    #         "pv0", 0
    #       ]
    #     }
    #   }
    # }
    lines += "\nlogical_volumes {\n"

    for entry in lvm_entries:
        name = entry["name"]
        uuid = entry["uuid"]
        size = entry["size"]
        start = entry["start"]
        lines += f"""
{name} {{
id = "{uuid}"
status = ["READ", "WRITE", "VISIBLE"]
flags = []
creation_time = 1620345600
creation_host = "builder"
segment_count = 1

segment1 {{
start_extent = 0
extent_count = {size}

type = "striped"
stripe_count = 1 # linear

stripes = [
"pv0", {start}
]
}}
}}
"""
    lines += "}\n}\n"

    return lines


def prepare_lvm_image(lvm_entries, image_file, vg_name, vg_uuid, pv_uuid):
    last = lvm_entries[-1]
    volumes_size = (last["start"] + last["size"]) * EXTENT_SIZE_BYTES
    image_size = LVM_HEADER_SIZE_BYTES + volumes_size

    os.close(os.open(image_file, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_EXCL, 0o600))
    os.truncate(image_file, image_size)

    structure_file = tempfile.mktemp()
    structure = generate_lvm_structure(lvm_entries, vg_name, vg_uuid, pv_uuid, image_size)
    with open(structure_file, "w") as f:
        f.write(structure)

    loop_device = ""
    with subprocess.Popen(["sudo", "losetup", "-P", "-f", "--show", image_file], stdout=subprocess.PIPE) as proc:
        loop_device = proc.stdout.readline().decode("UTF-8").strip()
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError("Failed to open loop device")

    subprocess.run(
        [
            "sudo",
            "lvm",
            "pvcreate",
            loop_device,
            "-u",
            pv_uuid,
            "--norestorefile",
            "--config",
            f'devices {{ filter=["a|{loop_device}|", "r|.*|"] }}',
        ],
        check=True,
    )
    subprocess.run(
        [
            "sudo",
            "lvm",
            "vgcfgrestore",
            "-f",
            structure_file,
            vg_name,
            "--config",
            f'devices {{ filter=["a|{loop_device}|", "r|.*|"] }}',
        ],
        check=True,
    )
    subprocess.run(["sudo", "losetup", "-d", loop_device], check=True)


def _copyfile(source, target, size):
    while size:
        count = min(16 * 1024, size)
        data = source.read(count)
        target.write(data)
        size -= len(data)


def write_partition_image_from_tar(lvm_entry, image_file, partition_tf):
    base = LVM_HEADER_SIZE_BYTES + (lvm_entry["start"] * EXTENT_SIZE_BYTES)
    with os.fdopen(os.open(image_file, os.O_RDWR), "wb+") as target:
        for member in partition_tf:
            if member.path != "partition.img":
                continue
            if member.size > lvm_entry["size"] * EXTENT_SIZE_BYTES:
                raise RuntimeError("Image too large for partition %s" % lvm_entry["name"])
            source = partition_tf.extractfile(member)
            if member.type == tarfile.GNUTYPE_SPARSE:
                for offset, size in member.sparse:
                    if size == 0:
                        continue
                    source.seek(offset)
                    target.seek(offset + base)
                    _copyfile(source, target, size)
            else:
                target.seek(base)
                _copyfile(source, target, member.size)


def select_partition_file(name, partition_files):
    for partition_file in partition_files:
        if name in os.path.basename(partition_file):
            return partition_file

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tar) file to write lvm image to", type=str)
    parser.add_argument("-v", "--volume_table", help="CSV file describing the volume table", type=str)
    parser.add_argument("-n", "--vg-name", metavar="vg_name", help="Volume Group name to use", type=str)
    parser.add_argument("-u", "--vg-uuid", metavar="vg_uuid", help="UUID to use for Volume Group", type=str)
    parser.add_argument("-p", "--pv-uuid", metavar="pv_uuid", help="UUID to use for Phisical Volume", type=str)
    parser.add_argument(
        "partitions",
        metavar="partition",
        type=str,
        nargs="+",
        help="Partitions to write. These must match the CSV volume table entries.",
    )

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    volume_desc_file = args.volume_table
    partition_files = list(args.partitions)
    vg_name = args.vg_name
    vg_uuid = args.vg_uuid
    pv_uuid = args.pv_uuid

    with open(volume_desc_file, "r") as f:
        lvm_entries = read_volume_description(f.read())
    validate_volume_table(lvm_entries)

    tmpdir = get_tmpdir_checking_block_size()

    lvm_image = os.path.join(tmpdir, "partition.img")
    prepare_lvm_image(lvm_entries, lvm_image, vg_name, vg_uuid, pv_uuid)

    for entry in lvm_entries:
        # Skip over any partitions starting with "B_". These are empty in our
        # published images, and stay this way until a live system upgrades
        # into them.
        if entry["name"].startswith("B_"):
            continue

        # Remove the "A_" prefix from any partitions before doing a lookup.
        prefix = "A_"
        name = entry["name"]
        if name.startswith(prefix):
            name = name[len(prefix) :]

        partition_file = select_partition_file(name, partition_files)

        if partition_file:
            write_partition_image_from_tar(entry, lvm_image, tarfile.open(partition_file, mode="r:"))
        else:
            print("No partition file for '%s' found, leaving empty" % name)

    subprocess.run(
        [
            "tar",
            "cf",
            out_file,
            "--sort=name",
            "--owner=root:0",
            "--group=root:0",
            "--mtime=UTC 1970-01-01 00:00:00",
            "--sparse",
            "-C",
            tmpdir,
            "partition.img",
        ],
        check=True,
    )

    print_artifact_info(out_file)


if __name__ == "__main__":
    main()
