#!/usr/bin/env python3
#
# Packs contents of a tar file into a vfat image (possibly taking only a
# subdirectory of the full tar file). The (sparse) vfat image itself is then
# wrapped into a tar file itself.
#
# Call example:
#   build_vfat_image -s 10M -o partition.img.tar -p boot/efi -i dockerimg.tar
#
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile


def untar_to_vfat(tf, fs_basedir, out_file, path_transform):
    """
    Put contents of tarfile into vfat image.

    Take all files in the given input tarfile "tf", and put them
    into the vfat image pointed to by "out_file". "fs_basedir" is
    used as temporary directory to unpack files to.

    path_transform converts the paths in the tarfile into target
    paths on the system (if it returns "None" for any input path,
    then the corresponding file/dir is dropped).
    """
    print(fs_basedir)
    for member in tf:
        path = path_transform(member.path)
        if path is None or path == "":
            continue
        if path[0] == "/":
            path = path[1:]
        if member.type == tarfile.DIRTYPE:
            if path == "":
                continue
            os.mkdir(os.path.join(fs_basedir, path))
            subprocess.run(["faketime", "1970-1-1 0", "mmd", "-i", out_file, "::/" + path], check=True)
        elif member.type == tarfile.REGTYPE or member.type == tarfile.AREGTYPE:
            with open(os.path.join(fs_basedir, path), "wb") as f:
                f.write(tf.extractfile(member).read())
            subprocess.run(
                ["faketime", "1970-1-1 0", "mcopy", "-o", "-i", out_file, os.path.join(fs_basedir, path), "::/" + path],
                check=True,
            )
        else:
            raise RuntimeError("Unhandled tar member kind: %s" % member.type)


def install_extra_files(out_file, extra_files):
    for extra_file in extra_files:
        source_file, install_target, mode = extra_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        subprocess.run(
            ["faketime", "1970-1-1 0", "mcopy", "-o", "-i", out_file, source_file, "::/" + install_target], check=True
        )


def parse_size(s):
    if s[-1] == "k" or s[-1] == "K":
        return 1024 * int(s[:-1])
    elif s[-1] == "m" or s[-1] == "M":
        return 1024 * 1024 * int(s[:-1])
    elif s[-1] == "g" or s[-1] == "G":
        return 1024 * 1024 * 1024 * int(s[:-1])
    else:
        return int(s)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--size", help="Size of image to build", type=str)
    parser.add_argument("-o", "--output", help="Target (tar) file to write partition image to", type=str)
    parser.add_argument(
        "-i", "--input", help="Source (tar) file to take files from", type=str, default="", required=False
    )
    parser.add_argument(
        "-p",
        "--path",
        help="Path to extract from tar file (only files below will be put into image",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "extra_files",
        metavar="extra_files",
        type=str,
        nargs="*",
        help="Extra files to install; expects list of sourcefile:targetfile:mode",
    )

    args = parser.parse_args(sys.argv[1:])

    in_file = args.input
    out_file = args.output
    image_size = parse_size(args.size)
    limit_prefix = args.path

    tmpdir = tempfile.mkdtemp()
    atexit.register(lambda: shutil.rmtree(tmpdir))

    fs_basedir = os.path.join(tmpdir, "fs")
    os.mkdir(fs_basedir)

    image_file = os.path.join(tmpdir, "partition.img")

    def path_transform(path, limit_prefix=limit_prefix):
        if path.startswith(limit_prefix):
            return path[len(limit_prefix) :]
        else:
            return None

    os.close(os.open(image_file, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_EXCL, 0o600))
    os.truncate(image_file, image_size)
    subprocess.run(["/usr/sbin/mkfs.vfat", "-i", "0", image_file], check=True)

    if in_file:
        with tarfile.open(in_file, mode="r|*") as tf:
            untar_to_vfat(tf, fs_basedir, image_file, path_transform)

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


if __name__ == "__main__":
    main()
