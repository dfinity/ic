#!/usr/bin/env python3
#
# Builds a lvm image from individual partition images and a volume
# table description. The actual lvm image is wrapped up into a tzst file
# because the raw file is sparse.
#
# The input partition images are also expected to be given as tzst files,
#
# Call example:
#   build_lvm_image -v volumes.csv -o partition-hostlvm.tzst part1.tzst part2.tzst ...
#
import argparse
import os
import subprocess
import sys
import tarfile

from crc import INITIAL_CRC, calc_crc

LVM_HEADER_SIZE_BYTES = int(2048 * 512)
BYTES_PER_MEBIBYTE = int(2 ** 20)
EXTENT_SIZE_BYTES = int(4 * BYTES_PER_MEBIBYTE)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tzst) file to write lvm image to", type=str)
    parser.add_argument("-v", "--volume_table", help="CSV file describing the volume table", type=str)
    parser.add_argument("-n", "--vg-name", metavar="vg_name", help="Volume Group name to use", type=str)
    parser.add_argument("-u", "--vg-uuid", metavar="vg_uuid", help="UUID to use for Volume Group", type=str)
    parser.add_argument("-p", "--pv-uuid", metavar="pv_uuid", help="UUID to use for Physical Volume", type=str)
    parser.add_argument(
        "partitions",
        metavar="partition",
        type=str,
        nargs="*",
        help="Partitions to write. These must match the CSV volume table entries.",
    )
    parser.add_argument("--dflate", help="Path to our dflate tool", type=str)

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

    tmpdir = os.getenv("ICOS_TEMP_DIR")
    if not tmpdir:
        raise "ICOS_TEMP_DIR env variable not available, should be set in BUILD script."

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
            write_partition_image_from_tzst(entry, lvm_image, partition_file)
        else:
            print("No partition file for '%s' found, leaving empty" % name)

    # We use our tool, dflate, to quickly create a sparse, deterministic, tar.
    # If dflate is ever misbehaving, it can be replaced with:
    # tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    temp_tar = os.path.join(tmpdir, "partition.tar")
    subprocess.run(
        [
            args.dflate,
            "--input",
            lvm_image,
            "--output",
            temp_tar,
        ],
        check=True,
    )

    subprocess.run(
        [
            "zstd",
            "-q",
            "--threads=0",
            temp_tar,
            "-o",
            out_file,
        ],
        check=True,
    )


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


def prepare_lvm_image(lvm_entries, image_file, vg_name, vg_uuid, pv_uuid):
    last = lvm_entries[-1]
    volumes_size = (last["start"] + last["size"]) * EXTENT_SIZE_BYTES
    image_size = LVM_HEADER_SIZE_BYTES + volumes_size

    # Create target file
    os.close(os.open(image_file, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_EXCL, 0o600))
    os.truncate(image_file, image_size)

    # Build segments
    header = _build_pv_header(pv_uuid, image_size)
    structure = _generate_lvm_structure(lvm_entries, vg_name, vg_uuid, pv_uuid, image_size)

    structure_bytes = structure.encode() + bytearray(b"\x00")  # NULL terminate the structure
    metadata = _build_pv_metadata(structure_bytes)

    # Write to file
    with os.fdopen(os.open(image_file, os.O_RDWR), "wb+") as target:
        # Write `header` at 512 bytes
        target.seek(512)
        target.write(header)
        # Write `metadata` at 4096 bytes
        target.seek(4096)
        target.write(metadata)
        # Write `structure` at 4096 + 512 bytes
        target.seek(4096 + 512)
        target.write(structure_bytes)


def select_partition_file(name, partition_files):
    for partition_file in partition_files:
        if name in os.path.basename(partition_file):
            return partition_file

    return None


def write_partition_image_from_tzst(lvm_entry, image_file, partition_tzst):
    tmpdir = os.getenv("ICOS_TEMP_DIR")
    if not tmpdir:
        raise "ICOS_TEMP_DIR env variable not available, should be set in BUILD script."

    partition_tf = os.path.join(tmpdir, "partition.tar")
    subprocess.run(["zstd", "-q", "--threads=0", "-f", "-d", partition_tzst, "-o", partition_tf], check=True)

    partition_tf = tarfile.open(partition_tf, mode="r:")
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


def _copyfile(source, target, size):
    while size:
        count = min(16 * 1024, size)
        data = source.read(count)
        target.write(data)
        size -= len(data)


def _build_pv_header(pv_uuid, image_size):
    # Partition Header
    # -----------------
    unchecked_area = bytearray()
    checked_area = bytearray()

    # Signature - 8 bytes
    unchecked_area += "LABELONE".encode().ljust(8, b"\x00")
    # Sector number - 8 bytes
    unchecked_area += (1).to_bytes(8, byteorder="little")
    # Checksum - 4 bytes
    # To be added after building the rest of the header
    # Data offset - 4 bytes
    checked_area += (32).to_bytes(4, byteorder="little")
    # Type indicator - 8 bytes
    checked_area += "LVM2 001".encode().ljust(8, b"\x00")

    # PV Header
    # ----------

    # PV UUID - 32 bytes
    checked_area += pv_uuid.replace("-", "").encode().ljust(32, b"\x00")
    # PV size - 8 bytes
    checked_area += image_size.to_bytes(8, byteorder="little")

    # Data area
    # Offset - 8 bytes
    checked_area += (BYTES_PER_MEBIBYTE).to_bytes(8, byteorder="little")
    # Size - 8 bytes
    checked_area += bytearray(8)  # 0 means: to end of disk
    # Terminator - 16 bytes
    checked_area += bytearray(16)

    # Metadata area
    # Offset - 8 bytes
    checked_area += (4096).to_bytes(8, byteorder="little")  # Start the metadata area on the second page
    # Size - 8 bytes
    checked_area += (BYTES_PER_MEBIBYTE - 4096).to_bytes(8, byteorder="little")  # End the metadata area at 1 Mebibyte
    # Terminator - 16 bytes
    checked_area += bytearray(16)

    # Extended header
    # Version - 4 bytes
    checked_area += (2).to_bytes(4, byteorder="little")
    # Flags - 4 bytes
    checked_area += (1).to_bytes(4, byteorder="little")  # 1 means: PV_EXT_USED

    # ----------

    # Pad to end of sector
    checked_area += bytearray(512 - (len(unchecked_area) + 4 + len(checked_area)))

    # Calculate CRC
    checksum = calc_crc(INITIAL_CRC, checked_area).to_bytes(4, byteorder="little")

    return unchecked_area + checksum + checked_area


def _generate_lvm_structure(lvm_entries, vg_name, vg_uuid, pv_uuid, size):
    # Define VG
    # ----------
    lines = f"""{vg_name} {{
id = "{vg_uuid}"

seqno = 1
format = "lvm2"
status = ["RESIZEABLE", "READ", "WRITE"]
flags = []
extent_size = 8192
max_lv = 0
max_pv = 0
metadata_copies = 0
"""

    # Define PVs
    # -----------
    dev_size = int(size / 512)  # Sector size
    pe_count = int((size - LVM_HEADER_SIZE_BYTES) / EXTENT_SIZE_BYTES)

    # Note: "/dev/nvme0n1p3" is just a hint, but can help speed up boot
    lines += f"""
physical_volumes {{
pv0 {{
id = "{pv_uuid}"

device = "/dev/nvme0n1p3"
status = ["ALLOCATABLE"]
flags = []
dev_size = {dev_size}
pe_start = 2048
pe_count = {pe_count}
}}
}}
"""

    # Add sections for LVs
    # ---------------------
    #
    # ----------
    # Example:
    # ----------
    # logical_volumes {
    # esp {
    # id = "qxkWcA-0XF7-scev-KJ2F-T4hY-c9xH-6tuqZ7"
    #
    # status = ["READ", "WRITE", "VISIBLE"]
    # flags = []
    # creation_time = 1620345600
    # creation_host = "builder"
    # segment_count = 1
    #
    # segment1 {
    # start_extent = 0
    # extent_count = 25
    #
    # type = "striped"
    # stripe_count = 1
    #
    # stripes = ["pv0", 0]
    # }
    # }
    # }
    lines += "\nlogical_volumes {"

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
stripe_count = 1

stripes = ["pv0", {start}]
}}
}}
"""
    lines += "}\n"

    # Close Structure
    # ----------------
    lines += "}"
    lines += """
contents = "Text Format Volume Group"
version = 1
creation_host = "builder"
creation_time = 1620345600

description = "Created by build_lvm_image.py."

"""

    return lines


def _build_pv_metadata(structure_bytes):
    # Metadata Header
    # ----------------
    metadata = bytearray()

    # Checksum - 4 bytes
    # To be added after building the rest of the header
    # Signature - 16 bytes
    metadata += " LVM2 x[5A%r0N*>".encode().ljust(16, b"\x00")
    # Version - 4 bytes
    metadata += (1).to_bytes(4, byteorder="little")
    # Offset - 8 bytes
    metadata += (4096).to_bytes(8, byteorder="little")  # Start the metadata area on the second page
    # Size - 8 bytes
    metadata += (BYTES_PER_MEBIBYTE - 4096).to_bytes(8, byteorder="little")  # End the metadata area at 1 Mebibyte

    # Location descriptors
    # Offset - 8 bytes
    metadata += (512).to_bytes(8, byteorder="little")
    # Size - 8 bytes
    metadata += (len(structure_bytes)).to_bytes(8, byteorder="little")
    # Checksum - 4 bytes
    metadata += calc_crc(INITIAL_CRC, structure_bytes).to_bytes(4, byteorder="little")
    # Flags - 4 bytes
    metadata += (0).to_bytes(4, byteorder="little")  # 0 means: no flags

    # ----------

    # Pad to end of sector
    metadata += bytearray(512 - (len(metadata) + 4))

    # Calculate CRC
    checksum = calc_crc(INITIAL_CRC, metadata).to_bytes(4, byteorder="little")

    return checksum + metadata


if __name__ == "__main__":
    main()
