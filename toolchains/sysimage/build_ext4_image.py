#!/usr/bin/env python3
#
# Packs contents of a tar file into a ext4 image (possibly taking only a
# subdirectory of the full tar file). The (sparse) ext4 image itself is then
# wrapped into a tzst file.
#
# Call example:
#   build_ext4_image -s 10M -o partition.img.tzst -p boot -i dockerimg.tar
#
import argparse
import atexit
import os
import subprocess
import sys
import tempfile


def strip_files(in_tar, strip_paths, out_tar):
    tmpdir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", tmpdir], check=True))

    fakeroot_statefile = os.path.join(tmpdir, "fakeroot.state")
    temp_dir = os.path.join(tmpdir, "files")
    subprocess.run(["mkdir", temp_dir])

    subprocess.run(["fakeroot", "-s", fakeroot_statefile, "tar", "xf", in_tar, "-C", temp_dir, "--selinux", "--xattrs"])

    for path in strip_paths:
        if path[0] == "/":
            path = path[1:]

        target_dir = os.path.join(temp_dir, path)
        if not os.path.exists(target_dir):
            continue

        for entry in os.listdir(target_dir):
            del_path = os.path.join(temp_dir, entry)
            subprocess.run(["fakeroot", "-i", fakeroot_statefile, "-s", fakeroot_statefile, "rm", "-rf", del_path])

    subprocess.run(["fakeroot", "-i", fakeroot_statefile, "tar", "cpf", out_tar, "-C", temp_dir, "--sort=name", "--selinux", "--xattrs", "."])


def make_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--size", help="Size of image to build", type=str)
    parser.add_argument("-o", "--output", help="Target (tzst) file to write partition image to", type=str)
    parser.add_argument(
        "-i", "--input", help="Source (tar) file to take files from", type=str, default="", required=False
    )
    parser.add_argument(
        "-p",
        "--path",
        help="Path to extract from tar file (only files below will be put into image)",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "--strip-paths",
        metavar="strip_paths",
        type=str,
        nargs="*",
        default=[],
        help="Directories to be cleared from the tree; expects a list of full paths",
    )
    parser.add_argument("-d", "--dflate", help="Path to dflate", type=str)
    parser.add_argument("-m", "--mke2fs-tool", help="Path to mke2fs tool", type=str, required=True, metavar="mke2fs_tool")
    return parser


def main():
    args = make_argparser().parse_args(sys.argv[1:])

    in_file = args.input
    out_file = args.output
    image_size = args.size
    limit_prefix = args.path
    strip_paths = args.strip_paths
    mke2fs_tool = args.mke2fs_tool

    if limit_prefix and limit_prefix[0] == "/":
        limit_prefix = limit_prefix[1:]

    tmpdir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", tmpdir], check=True))

    image_file = os.path.join(tmpdir, "partition.img")

    if in_file and strip_paths:
        stripped_tar = os.path.join(tmpdir, "stripped.tar")
        strip_files(in_file, strip_paths, stripped_tar)
        in_file = stripped_tar

    # XXX This is much slower than old code, should go back to it if used in future
    # XXX Reuse strip_files code for limit_prefix, this is a hack that only works for a prefix of `/boot`, but this is the only case we have, now
    if limit_prefix:
        limited_tar = os.path.join(tmpdir, "limited.tar")
        strip_files(in_file, ["/bin","/dev","/etc","/home","/lib","/lib32","/lib64","/libx32","/media","/mnt","/opt","/proc","/root","/run","/sbin","/srv","/sys","/tmp","/usr","/var"], limited_tar)
        in_file = limited_tar

    mke2fs_args = [mke2fs_tool, "-F", "-t", "ext4"]
    if in_file:
        mke2fs_args += ["-d", in_file]
    mke2fs_args += [image_file, str(image_size)]
    subprocess.run(mke2fs_args, check=True)
    # XXX env={"E2FSPROGS_FAKE_TIME": "0"} Potentially faketime, too

    # If dflate is ever misbehaving, it can be replaced with:
    # tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    temp_tar = os.path.join(tmpdir, "partition.tar")
    subprocess.run(
        [
            args.dflate,
            "--input",
            image_file,
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


if __name__ == "__main__":
    main()
