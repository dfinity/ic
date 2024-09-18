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


def write_partition_image(gpt_entry, target_path, partition_image_path):
    base = gpt_entry["start"] * 512
    subprocess.run(
        ["dd", f"if={partition_image_path}", f"seek={base}", f"of={target_path}",
         "conv=sparse", "oflag=seek_bytes", "bs=1M"],
        check=True)


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

    prepare_diskimage(gpt_entries, out_file)

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
            name = name[len(prefix):]

        partition_file = select_partition_file(name, partition_files)

        if partition_file:
            write_partition_image(entry, out_file, partition_file)
        else:
            print("No partition file for '%s' found, leaving empty" % name)

    # Provide additional space for vda10, the final partition, for immediate QEMU use
    if args.expanded_size:
        subprocess.run(["truncate", "--size", args.expanded_size, out_file], check=True)


if __name__ == "__main__":
    main()
