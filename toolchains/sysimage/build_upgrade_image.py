#!/usr/bin/env python3
#
# Builds an upgrade image from individual partition images.
#
# Call example:
#   build_upgrade_image -o upgrade.tar.zst -b boot.img.tzst -r root.img.tzst -v version.txt
#
import argparse
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
    parser.add_argument("--dflate", help="Path to our dflate tool", type=str)
    parser.add_argument("--overlay", help="Optional overlay image (SquashFS .raw) for Phase 1 fast upgrade", type=str, default=None)

    args = parser.parse_args(sys.argv[1:])

    out_file = args.out
    root_image = args.root
    boot_image = args.boot
    version_file = args.versionfile
    overlay_image = args.overlay

    tmpdir = tempfile.mkdtemp()

    boot_path = os.path.join(tmpdir, "boot.img")
    subprocess.run(["tar", "xf", boot_image, "--transform=s/partition.img/boot.img/", "-C", tmpdir], check=True)

    root_path = os.path.join(tmpdir, "root.img")
    subprocess.run(["tar", "xf", root_image, "--transform=s/partition.img/root.img/", "-C", tmpdir], check=True)

    version_path = os.path.join(tmpdir, "VERSION.TXT")
    shutil.copy(version_file, version_path, follow_symlinks=True)

    dflate_inputs = [boot_path, root_path, version_path]

    # Copy the overlay image into the upgrade tar if present.
    if overlay_image and os.path.exists(overlay_image):
        overlay_path = os.path.join(tmpdir, "overlay.raw")
        shutil.copy2(overlay_image, overlay_path)
        dflate_inputs.append(overlay_path)

    dflate_args = [args.dflate]
    for inp in dflate_inputs:
        dflate_args.extend(["--input", inp])
    dflate_args.extend(["--output", out_file])
    subprocess.run(dflate_args, check=True)

    # tempfile cleanup is handled by proc_wrapper.sh


if __name__ == "__main__":
    main()
