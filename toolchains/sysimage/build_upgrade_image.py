#!/usr/bin/env python3
#
# Builds an upgrade image from individual partition images.
#
# Call example:
#   build_upgrade_image -o upgrade.tar.gz -b boot.img.tzst -r root.img.tzst -v version.txt
#
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", help="Target (tar) file to write upgrade package to", type=str)
    parser.add_argument("-b", "--boot", help="The (tzst) boot filesystem image", type=str)
    parser.add_argument("-r", "--root", help="The (tzst) root filesystem image", type=str)
    parser.add_argument("-v", "--versionfile", help="The version file in the upgrade image", type=str)
    parser.add_argument("-d", "--dflate", help="Path to dflate", type=str)

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    root_image = args.root
    boot_image = args.boot
    version_file = args.versionfile

    tmpdir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", tmpdir], check=True))

    boot_path = os.path.join(tmpdir, "boot.img")
    subprocess.run(["tar", "xf", boot_image, "--transform=s/partition.img/boot.img/", "-C", tmpdir], check=True)

    root_path = os.path.join(tmpdir, "root.img")
    subprocess.run(["tar", "xf", root_image, "--transform=s/partition.img/root.img/", "-C", tmpdir], check=True)

    version_path = os.path.join(tmpdir, "VERSION.TXT")
    shutil.copy(version_file, version_path, follow_symlinks=True)

    # If dflate is ever misbehaving, it can be replaced with:
    # tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    subprocess.run(
        [
            args.dflate,
            "--input",
            boot_path,
            "--input",
            root_path,
            "--input",
            version_path,
            "--output",
            out_file,
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
