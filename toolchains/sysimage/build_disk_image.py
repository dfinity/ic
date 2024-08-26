#!/usr/bin/env python3
#
# Builds a disk image from individual partition images and a partition
# table description. The actual disk image is wrapped up into a tar file
# because the raw image file is sparse.
#
# The input partition images are also expected to be given as tzst files,
#
# Call example:
#   build_disk_image -p partitions.csv -o disk.img.tar part1.tzst part2.tzst ...
#
import argparse
import os
import subprocess
import sys
import tarfile


def read_partition_description(data):
    gpt_entries = []
    for line in data.split("\n"):
        if line.startswith("#") or not line:
            continue
        cols = tuple(map(lambda s: s.strip(), line.split(",")))
        gpt_entries.append(
            {
                "name": cols[0],
                "start": int(cols[1]),
                "size": int(cols[2]),
                "type": cols[3],
                "uuid": cols[4],
                "description": cols[5],
            }
        )
    return gpt_entries


def validate_partition_table(gpt_entries):
    """
    Validate partition table.

    Validate that partitions do not overlap, start at suitable
    boundaries, and have sane types.
    """
    end = 2048
    for entry in gpt_entries:
        if entry["start"] < end:
            raise RuntimeError("Partition %s overlaps with previous" % entry["name"])
        if (entry["start"] % 2048) != 0:
            raise RuntimeError("Partition %s start is not aligned to 1MB boundary" % entry["name"])
        if (entry["size"] % 2048) != 0:
            raise RuntimeError("Partition %s size is not aligned to 1MB boundary" % entry["name"])
        if not entry["type"] in ("U", "L", "M"):
            raise RuntimeError("Partition %s has unsupported type" % entry["name"])
        end = entry["start"] + entry["size"]


def generate_sfdisk_script(gpt_entries):
    type_map = {
        # UEFI partition type
        "U": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        # Linux partition type
        "L": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        # Microsoft basic data
        "M": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    }
    lines = ["label: gpt", "label-id: 2B110BB7-CDEC-7D41-B97E-893EDCBE5428"]
    for entry in gpt_entries:
        lines.append(
            "start=%d,size=%d,type=%s,uuid=%s" % (entry["start"], entry["size"], type_map[entry["type"]], entry["uuid"])
        )
    return "\n".join(lines) + "\n"


def prepare_diskimage(gpt_entries, image_file):
    last = gpt_entries[-1]
    image_size = (last["start"] + last["size"] + 2048) * 512

    os.close(os.open(image_file, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_EXCL, 0o600))
    os.truncate(image_file, image_size)

    with subprocess.Popen(["/usr/sbin/sfdisk", image_file], stdin=subprocess.PIPE) as proc:
        proc.stdin.write(generate_sfdisk_script(gpt_entries).encode("utf-8"))
        proc.stdin.close()
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError("Build of partition table failed")


def _copyfile(source, target, size):
    while size:
        count = min(16 * 1024, size)
        data = source.read(count)
        target.write(data)
        size -= len(data)


def write_partition_image_from_tzst(gpt_entry, image_file, partition_tzst):
    tmpdir = os.getenv("ICOS_TEMP_DIR")
    if not tmpdir:
        raise "ICOS_TEMP_DIR env variable not available, should be set in BUILD script."

    partition_tf = os.path.join(tmpdir, "partition.tar")
    subprocess.run(["zstd", "-q", "--threads=0", "-f", "-d", partition_tzst, "-o", partition_tf], check=True)

    partition_tf = tarfile.open(partition_tf, mode="r:")
    base = gpt_entry["start"] * 512
    with os.fdopen(os.open(image_file, os.O_RDWR), "wb+") as target:
        for member in partition_tf:
            if member.path != "partition.img":
                continue
            if member.size > gpt_entry["size"] * 512:
                raise RuntimeError("Image too large for partition %s" % gpt_entry["name"])
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
    parser.add_argument("-o", "--out", help="Target (tar) file to write disk image to", type=str)
    parser.add_argument("-p", "--partition_table", help="CSV file describing the partition table", type=str)
    parser.add_argument("-s", "--expanded-size", help="Optional size to grow the image to", required=False, type=str)
    parser.add_argument(
        "partitions",
        metavar="partition",
        type=str,
        nargs="*",
        help="Partitions to write. These must match the CSV partition table entries.",
    )
    parser.add_argument("--dflate", help="Path to our dflate tool", type=str)

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    partition_desc_file = args.partition_table
    partition_files = list(args.partitions)

    with open(partition_desc_file, "r") as f:
        gpt_entries = read_partition_description(f.read())
    validate_partition_table(gpt_entries)

    tmpdir = os.getenv("ICOS_TEMP_DIR")
    if not tmpdir:
        raise "ICOS_TEMP_DIR env variable not available, should be set in BUILD script."

    disk_image = os.path.join(tmpdir, "disk.img")
    prepare_diskimage(gpt_entries, disk_image)

    for entry in gpt_entries:
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
            write_partition_image_from_tzst(entry, disk_image, partition_file)
        else:
            print("No partition file for '%s' found, leaving empty" % name)

    # Provide additional space for vda10, the final partition, for immediate QEMU use
    if args.expanded_size:
        subprocess.run(["truncate", "--size", args.expanded_size, disk_image], check=True)

    # We use our tool, dflate, to quickly create a sparse, deterministic, tar.
    # If dflate is ever misbehaving, it can be replaced with:
    # tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    subprocess.run(
        [
            args.dflate,
            "--input",
            disk_image,
            "--output",
            out_file,
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
