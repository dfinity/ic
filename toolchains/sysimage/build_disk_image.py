#!/usr/bin/env python3
#
# Builds a disk image from individual partition images and a partition
# table description. The actual disk image is wrapped up into a tar file
# because the raw image file is sparse.
#
# The input partition images are also expected to be given as tar files,
# where each tar archive must contain a single file named "partition.img".
#
# Call example:
#   build_disk_image -p partitions.csv -o disk.img.tar part1.tar part2.tar ...
#
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile


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
        if not entry["type"] in ("U", "L"):
            raise RuntimeError("Partition %s has unsupported type" % entry["name"])
        end = entry["start"] + entry["size"]


def generate_sfdisk_script(gpt_entries):
    type_map = {
        # UEFI partition type
        "U": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        # Linux partition type
        "L": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
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


def write_partition_image_from_tar(gpt_entry, image_file, partition_tf):
    base = gpt_entry["start"] * 512
    with os.fdopen(os.open(image_file, os.O_RDWR), "wb+") as target:
        for member in partition_tf:
            if member.path != "partition.img":
                continue
            if member.size > gpt_entry["size"] * 512:
                raise RuntimeError("Image too large for partition %s" % gpt_entry["name"])
            if member.type == tarfile.GNUTYPE_SPARSE:
                source = partition_tf.extractfile(member)
                for offset, size in member.sparse:
                    if size == 0:
                        continue
                    source.seek(offset)
                    target.seek(offset + base)
                    _copyfile(source, target, size)
            else:
                target.seek(base)
                _copyfile(source, target, member.size)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tar) file to write disk image to", type=str)
    parser.add_argument("-p", "--partition_table", help="CSV file describing the partition table", type=str)
    parser.add_argument("partitions", metavar="partition", type=str, nargs="+", help="Partitions to write, in order")

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    partition_desc_file = args.partition_table
    partition_files = list(args.partitions)

    with open(partition_desc_file, "r") as f:
        gpt_entries = read_partition_description(f.read())
    validate_partition_table(gpt_entries)

    tmpdir = tempfile.mkdtemp()
    atexit.register(lambda: shutil.rmtree(tmpdir))

    disk_image = os.path.join(tmpdir, "disk.img")
    prepare_diskimage(gpt_entries, disk_image)

    for index in range(len(partition_files)):
        write_partition_image_from_tar(gpt_entries[index], disk_image, tarfile.open(partition_files[index], mode="r:"))

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
            "disk.img",
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
