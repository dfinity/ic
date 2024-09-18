#!/usr/bin/env python3
#
# Builds an upgrade image from individual partition images.
#
# Call example:
#   build_upgrade_image -o upgrade.tar -b boot.img -r root.img -v version.txt
#
import argparse
import os
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tar) file to write upgrade package to", type=str)
    parser.add_argument("-b", "--boot", help="The (tzst) boot filesystem image", type=str)
    parser.add_argument("-r", "--root", help="The (tzst) root filesystem image", type=str)
    parser.add_argument("-v", "--versionfile", help="The version file in the upgrade image", type=str)
    parser.add_argument("--dflate", help="Path to our dflate tool", type=str)

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    root_image = args.root
    boot_image = args.boot
    version_file = args.versionfile

    # We use our tool, dflate, to quickly create a sparse, deterministic, tar.
    # If dflate is ever misbehaving, it can be replaced with:
    # tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    subprocess.run(
        [
            args.dflate,
            "--input",
            boot_image,
            "--input",
            root_image,
            "--input",
            version_file,
            "--output",
            out_file,
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
