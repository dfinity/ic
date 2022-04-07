#!/usr/bin/env python3
#
# Packs contents of a tar file into a ext4 image (possibly taking only a
# subdirectory of the full tar file). The (sparse) ext4 image itself is then
# wrapped into a tar file itself.
#
# Call example:
#   build_ext4_image -s 10M -o partition.img.tar -p boot -i dockerimg.tar -S file_contexts
#
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tempfile


def parse_size(s):
    if s[-1] == "k" or s[-1] == "K":
        return 1024 * int(s[:-1])
    elif s[-1] == "m" or s[-1] == "M":
        return 1024 * 1024 * int(s[:-1])
    elif s[-1] == "g" or s[-1] == "G":
        return 1024 * 1024 * 1024 * int(s[:-1])
    else:
        return int(s)


def limit_file_contexts(file_contexts, base_path):
    r"""
    Projects file contexts to given base path.

    Takes an SELinux filecontext file describing the entire
    system and extracts all statements that refer to the given
    base_path. All statements not relating to that base_path are
    deleted, and all paths are adjusted such that the common
    path prefix is removed.

    Example: given this file_context input:

        /.*     system_u:object_r:default_t:s0
        /a?quota\.(user|group)  --      system_u:object_r:quota_db_t:s0
        /boot/.*        system_u:object_r:boot_t:s0
        /boot/efi(/.*)?/System\.map(-.*)?       --      system_u:object_r:system_map_t:s0
        /boot/lost\+found/.*    <<none>>


    and base_path="/boot/" will produce this output:

        .*        system_u:object_r:boot_t:s0
        efi(/.*)?/System\.map(-.*)?       --      system_u:object_r:system_map_t:s0

    """
    lines = []
    for line in file_contexts.split("\n"):
        # Drop all statements assigning no label at all
        if line.find("<<none>>") != -1:
            continue
        if line.startswith(base_path):
            lines.append(line[len(base_path) :])
    return "\n".join(lines) + "\n"


def get_root_context(file_contexts, base_path):
    for line in file_contexts.split("\n"):
        pieces = line.split()
        if len(pieces) >= 3 and pieces[0] == base_path and pieces[1] == "-d":
            return pieces[2]
    raise RuntimeError("Could determine SELinux context for root inode")


def read_fakeroot_state(statefile):
    """
    Reads fakeroot state file, key by inode.

    fakeroot state file has the following structure:
        dev=fd03,ino=136887,mode=100600,uid=0,gid=0,nlink=1,rdev=0
        dev=fd02,ino=3932193,mode=100600,uid=0,gid=0,nlink=1,rdev=0

    Read all fields by line into a dictionary, and keep this
    dictionary keyed by inode number.
    """
    entry_by_inode = {}
    for line in open(statefile, "r").readlines():
        d = {}
        for item in line[:-1].split(","):
            k, v = item.split("=")
            d[k] = v
        entry_by_inode[int(d["ino"])] = d
    return entry_by_inode


def install_extra_files(fs_basedir, fakeroot_statefile, extra_files):
    for extra_file in extra_files:
        source_file, install_target, mode = extra_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        install_target = os.path.join(fs_basedir, install_target)
        shutil.copy(source_file, install_target)
        os.chmod(install_target, int(mode, 8))
        subprocess.run(
            ["fakeroot", "-s", fakeroot_statefile, "-i", fakeroot_statefile, "chown", "root.root", install_target]
        )


def prepare_tree_from_tar(in_file, fakeroot_statefile, fs_basedir, limit_prefix):
    if in_file:
        subprocess.run(
            [
                "fakeroot",
                "-s",
                fakeroot_statefile,
                "tar",
                "xf",
                in_file,
                "--numeric-owner",
                "-C",
                fs_basedir,
                limit_prefix,
            ],
            check=True,
        )
    else:
        subprocess.run(
            [
                "fakeroot",
                "-s",
                fakeroot_statefile,
                "chown",
                "root.root",
                fs_basedir,
            ],
            check=True,
        )


def fixup_selinux_root_context(file_contexts, limit_prefix, image_file):
    root_context = get_root_context(file_contexts, "/" + limit_prefix[:-1])
    with subprocess.Popen(
        ["/usr/sbin/debugfs", "-w", image_file], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL
    ) as proc:
        proc.stdin.write(('ea_set / security.selinux "%s\\000"\n' % root_context).encode("utf-8"))
        proc.stdin.close()
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError("SELinux root context fixup failed")


def fixup_permissions(fs_rootdir, fakeroot_statefile, image_file):
    fakeroot_state = read_fakeroot_state(fakeroot_statefile)
    for path, subdirs, files in os.walk(fs_rootdir, followlinks=False):
        for entry in subdirs + files:
            realpath = os.path.join(path, entry)
            imgpath = os.path.join(path[len(fs_rootdir) :], entry)
            ino = os.lstat(realpath).st_ino
            entry = fakeroot_state[ino]
            uid = entry["uid"]
            gid = entry["gid"]
            if uid != "0" or gid != "0":
                print("Fix ownership of %s to %s:%s" % (imgpath, uid, gid))
                with subprocess.Popen(
                    ["/usr/sbin/debugfs", "-w", image_file, "-R", "modify_inode " + imgpath],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                ) as proc:
                    proc.stdin.write(("\n%s\n%s\n" % (uid, gid)).encode("utf-8"))
                    proc.stdin.close()
                    proc.wait()
                    if proc.returncode != 0:
                        raise RuntimeError("Permission fixup failed")


def make_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--size", help="Size of image to build", type=str)
    parser.add_argument("-o", "--output", help="Target (tar) file to write partition image to", type=str)
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
        "-S",
        "--file_contexts",
        help="Path to SELinux file_contexts description file",
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
    return parser


def main():
    args = make_argparser().parse_args(sys.argv[1:])

    in_file = args.input
    out_file = args.output
    image_size = parse_size(args.size)
    limit_prefix = args.path
    file_contexts_file = args.file_contexts
    extra_files = args.extra_files
    if limit_prefix and limit_prefix[0] == "/":
        limit_prefix = limit_prefix[1:]

    tmpdir = tempfile.mkdtemp()
    atexit.register(lambda: shutil.rmtree(tmpdir))

    if file_contexts_file:
        original_file_contexts = open(file_contexts_file, "r").read()
        file_contexts = limit_file_contexts(original_file_contexts, "/" + limit_prefix)
        file_contexts_file = os.path.join(tmpdir, "file_contexts")
        open(file_contexts_file, "w").write(file_contexts)

    fs_basedir = os.path.join(tmpdir, "fs")
    fakeroot_statefile = os.path.join(tmpdir, "fakeroot.state")
    os.mkdir(fs_basedir)
    image_file = os.path.join(tmpdir, "partition.img")

    # Prepare a filesystem tree that represents what will go into
    # the fs image. Wrap everything in fakeroot so permissions and
    # ownership will be preserved while unpacking (see below).
    prepare_tree_from_tar(in_file, fakeroot_statefile, fs_basedir, limit_prefix)
    install_extra_files(fs_basedir, fakeroot_statefile, extra_files)

    # Now build the basic filesystem image. Wrap again in fakeroot
    # so correct permissions are read for all files etc.
    make_ext4fs_args = ["fakeroot", "-i", fakeroot_statefile, "make_ext4fs", "-T", "0", "-l", str(image_size)]
    make_ext4fs_args += [image_file, os.path.join(fs_basedir, limit_prefix)]
    if file_contexts_file:
        make_ext4fs_args += ["-S", file_contexts_file]
    subprocess.run(make_ext4fs_args, check=True)

    # make_ext4fs has two quirks/bugs that will be fixed up now.

    # 1. SELinux context of the root inode does not get set correctly.
    if file_contexts_file:
        fixup_selinux_root_context(original_file_contexts, limit_prefix, image_file)

    # 2. Ownership of all inodes is root.root, but that is not what it is
    # supposed to be in the final image
    fixup_permissions(os.path.join(fs_basedir, limit_prefix), fakeroot_statefile, image_file)

    # Wrap the built filesystem image up in a tar file. Use sparse to
    # deflate all the zeroes left unwritten during build.
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
