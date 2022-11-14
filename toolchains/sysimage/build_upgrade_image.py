#!/usr/bin/env python3
#
# Builds an upgrade image from individual partition images.
#
# Call example:
#   build_upgrade_image -o upgrade.tar.gz -b boot.img.tar -r root.img.tar -v version.txt -c gzip
#
import argparse
import shutil
import subprocess
import sys

from reproducibility import get_tmpdir_checking_block_size
from reproducibility import print_artifact_info

COMPRESSOR_PROGRAMS = {
    "gz": ["--use-compress-program=gzip"],
    "gzip": ["--use-compress-program=gzip"],
    "zstd": ["--use-compress-program=zstd --threads=0 -10"],
    "": [],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tar) file to write upgrade package to", type=str)
    parser.add_argument("-b", "--boot", help="The (tarred) boot filesystem image", type=str)
    parser.add_argument("-r", "--root", help="The (tarred) root filesystem image", type=str)
    parser.add_argument("-v", "--versionfile", help="The version file in the upgrade image", type=str)
    parser.add_argument("-c", "--compression", help="Compression format of upgrade package", type=str, default="")

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    root_image = args.root
    boot_image = args.boot
    version_file = args.versionfile
    compression = args.compression

    tmpdir = get_tmpdir_checking_block_size()

    subprocess.run(["tar", "xf", boot_image, "--transform=s/partition.img/boot.img/", "-C", tmpdir], check=True)

    subprocess.run(["tar", "xf", root_image, "--transform=s/partition.img/root.img/", "-C", tmpdir], check=True)
    shutil.copy(version_file, tmpdir + "/VERSION.TXT", follow_symlinks=True)
    subprocess.run(
        [
            "tar",
            "cf",
            out_file,
            "--sort=name",
            "--owner=root:0",
            "--group=root:0",
            "--mtime=UTC 1970-01-01 00:00:00",
        ]
        + COMPRESSOR_PROGRAMS[compression]
        + [
            "--sparse",
            "-C",
            tmpdir,
            ".",
        ],
        check=True,
    )

    print_artifact_info(out_file)


if __name__ == "__main__":
    main()
