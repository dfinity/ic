#!/usr/bin/env python3
#
# Runs a docker build and extract the built container as a single flattened
# tar file. All timestamps and other non-reproducible effects of docker build
# (e.g. order of files) are squashed in order to build a reproducible tarball.
#
# The script is expected to be called with the arguments to be given to "docker build".
# The resulting tar file will be written to stdout.
#
# Call example:
#   docker_tar dockerdir --build-arg foo=bar > tree.tar
#
from __future__ import annotations

import argparse
import atexit
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import typing

from reproducibility import print_artifact_info

image_hash_re = re.compile("((Successfully built )|(.*writing image sha256:))([0-9a-f]+).*")


def docker_build(args, dockerfile):
    """
    Runs 'docker build' and return image hash.

    Runs "docker build" with the given additional arguments to the call.
    The build logs will be passed through to stderr. Upon successful
    completion, the hash of the built docker image is returned by this
    function.
    """
    image_id_filename = tempfile.mktemp()
    docker_args = ["docker", "build", "--iidfile", image_id_filename] + args
    if dockerfile:
        docker_args.append("--file")
        docker_args.append(dockerfile)

    image_hash = None

    proc = subprocess.run(docker_args)
    proc_call_info = f"Docker args: {docker_args}, cwd: {os.getcwd()}"
    if proc.returncode != 0:
        raise RuntimeError("Docker build failed. " + proc_call_info)
    atexit.register(lambda: os.remove(image_id_filename))

    hash_line = None
    with open(image_id_filename, "r") as image_id_file:
        hash_line = image_id_file.readline()
    err_text = f"Failed to parse image hash. {proc_call_info}"
    assert hash_line and hash_line.startswith("sha256:") and len(hash_line) == 71, err_text
    image_hash = hash_line[7:]
    return image_hash


def _read_tar_contents(filename):
    """Reads tar file as map from filename -> content."""
    with tarfile.open(name=filename, mode="r|*") as tf:

        filemap = {}
        for member in tf:
            buf = member.tobuf()  # noqa - no idea why buf is here
            if member.type == tarfile.REGTYPE:
                filemap[member.name] = tf.extractfile(member).read()
            elif (member.type == tarfile.LNKTYPE) or (member.type == tarfile.SYMTYPE):
                filemap[member.name] = member.linkname[3:]
    return filemap


def _get_layer_data(filemap):
    """Gets the docker layer data from the filemap in correct order."""
    manifest = json.loads(filemap["manifest.json"])
    layers = manifest[0]["Layers"]

    out = []
    for layer in layers:
        if isinstance(filemap[layer], str):
            out.append(filemap[filemap[layer]])
        else:
            out.append(filemap[layer])

    return tuple(out)


class Inode(object):
    def __init__(self, mode, uid, gid, uid_name, gid_name):
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.uid_name = uid_name
        self.gid_name = gid_name


class DirInode(Inode):
    def __init__(self, mode, uid, gid, uid_name, gid_name, entries={}):
        Inode.__init__(self, mode, uid, gid, uid_name, gid_name)
        self.entries = entries.copy()


class LinkInode(Inode):
    def __init__(self, mode, uid, gid, uid_name, gid_name, target):
        Inode.__init__(self, mode, uid, gid, uid_name, gid_name)
        self.target = target


class RegInode(Inode):
    def __init__(self, mode, uid, gid, uid_name, gid_name, contents):
        Inode.__init__(self, mode, uid, gid, uid_name, gid_name)
        self.contents = contents


class FS:
    def __init__(self):
        self.root = DirInode(0o755, 0, 0, "root", "root")

    def clear_dir(self, path):
        self._lookup(path).entries.clear()

    def unlink(self, path):
        basename = os.path.basename(path)
        dirname = os.path.dirname(path)

        parent = self._lookup(dirname)
        del parent.entries[basename]

    def add_dir(self, path, mode, uid, gid, uid_name, gid_name):
        basename = os.path.basename(path)
        dirname = os.path.dirname(path)

        parent = self._lookup(dirname)
        if basename in parent.entries:
            if type(parent.entries[basename]) is not DirInode:
                raise RuntimeError("Expected entry is not a directory in base layer: " + path)
            else:
                parent.entries[basename].mode = mode
                parent.entries[basename].uid = uid
                parent.entries[basename].gid = gid
                parent.entries[basename].uid_name = uid_name
                parent.entries[basename].gid_name = gid_name
        else:
            parent.entries[basename] = DirInode(mode, uid, gid, uid_name, gid_name)

    def add_link(self, path, mode, uid, gid, uid_name, gid_name, target):
        basename = os.path.basename(path)
        dirname = os.path.dirname(path)

        self._lookup(dirname).entries[basename] = LinkInode(mode, uid, gid, uid_name, gid_name, target)

    def add_reg(self, path, mode, uid, gid, uid_name, gid_name, content):
        basename = os.path.basename(path)
        dirname = os.path.dirname(path)

        self._lookup(dirname).entries[basename] = RegInode(mode, uid, gid, uid_name, gid_name, content)

    def chmod(self, path, mode):
        inode = self._lookup(path)
        inode.mode = mode

    def _lookup(self, path):
        current = self.root
        for part in path.split("/"):
            if part != "":
                current = current.entries[part]
        return current

    def ls_dir(self, dir, indent=""):
        for key in sorted(dir.entries.keys()):
            print(indent + key + " " + str(dir.entries[key]))
            if type(dir.entries[key]) is DirInode:
                self.ls_dir(dir.entries[key], indent + " ")

    def ls(self):
        self.ls_dir(self.root)

    def write_hashes(self, output, dir=None, prefix="/"):
        if dir is None:
            dir = self.root
        for key in sorted(dir.entries.keys()):
            output.write(prefix)
            entry = dir.entries[key]
            if type(entry) is DirInode:
                output.write(f"{key}/\n")
                self.write_hashes(output, entry, f"  {prefix}{key}/")
            elif type(entry) is LinkInode:
                output.write(f"{key} -> {entry.target}\n")
            elif type(entry) is RegInode:
                hash = hashlib.sha256(entry.contents).hexdigest()
                output.write(f"{key} sha256#{hash}\n")


def _process_layer(layer, fs):
    tf = tarfile.open(fileobj=io.BytesIO(layer), mode="r")

    # Process all members in the tarfile. They are either ordinary
    # dirs/files/symlinks to be extracted, or they are "white-out" files:
    # These direct to delete certain underlying files from previous layer.
    for member in tf:
        basename = os.path.basename(member.path)
        dirname = os.path.dirname(member.path)
        if basename == ".wh..wh..opq":
            fs.clear_dir(dirname)
        elif basename.startswith(".wh."):
            fs.unlink(os.path.join(dirname, basename[4:]))
        else:
            if member.type == tarfile.DIRTYPE:
                fs.add_dir(member.path, member.mode, member.uid, member.gid, member.uname, member.gname)
            elif member.type == tarfile.REGTYPE or member.type == tarfile.AREGTYPE:
                fs.add_reg(
                    member.path,
                    member.mode,
                    member.uid,
                    member.gid,
                    member.uname,
                    member.gname,
                    tf.extractfile(member).read(),
                )
            elif member.type == tarfile.LNKTYPE or member.type == tarfile.SYMTYPE:
                fs.add_link(
                    member.path, member.mode, member.uid, member.gid, member.uname, member.gname, member.linkname
                )
            else:
                raise RuntimeError("Unhandled tar member kind")


def docker_extract_fs(image_hash):
    """
    Extracts the image via 'docker save' and builds fs.

    Extract the docker image identified by the given hash.
    Flatten all the layers and build a temporary in-memory
    filesystem representation of the image.
    """
    tar_name = tempfile.mktemp(suffix=".tar")
    atexit.register(lambda: os.remove(tar_name))
    with subprocess.Popen(["docker", "save", image_hash, "-o", tar_name], stdout=subprocess.PIPE) as proc:
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError("Docker save failed")
        layer_filemap = _read_tar_contents(tar_name)

    layers = _get_layer_data(layer_filemap)
    fs = FS()
    for layer in layers:
        _process_layer(layer, fs)

    # These files are not properly controlled inside docker: they are
    # bind-mounted, and docker build cannot set their permissions. Fix this
    # up on extracting the docker save file here.
    fs.chmod("etc/hosts", 0o644)
    fs.chmod("etc/hostname", 0o644)
    fs.chmod("etc/resolv.conf", 0o644)

    return fs


def _recurse_add_to_tar(path_prefix, dir_node, tf):
    for name in sorted(dir_node.entries.keys()):
        inode = dir_node.entries[name]
        ti = tarfile.TarInfo(path_prefix + name)
        ti.size = 0
        ti.mtime = 0
        ti.mode = inode.mode
        ti.uid = inode.uid
        ti.gid = inode.gid
        ti.uname = inode.uid_name
        ti.gname = inode.gid_name
        if type(inode) is DirInode:
            ti.type = tarfile.DIRTYPE
            tf.addfile(ti)
            _recurse_add_to_tar(path_prefix + name + "/", inode, tf)
        elif type(inode) is LinkInode:
            ti.type = tarfile.SYMTYPE
            ti.linkname = inode.target
            tf.addfile(ti)
        elif type(inode) is RegInode:
            ti.type = tarfile.AREGTYPE
            ti.size = len(inode.contents)
            tf.addfile(ti, io.BytesIO(inode.contents))
        else:
            raise RuntimeError("Unhandled inode kind")


def tar_fs(fs, outfile):
    """
    Tar up the filesystem tree.

    Recursively archive the given filesystem tree as a tar
    archive into the given file. All files are written with
    "zero" timestamps and in deterministic order in order
    to generate reproducible results.
    """
    tf = tarfile.open(fileobj=outfile, mode="w")

    _recurse_add_to_tar("", fs.root, tf)


def make_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--skip-pull", help="Don't attempt to pull image from dockerhub.", default=False, action="store_true"
    )
    parser.add_argument("-o", "--output", help="Target (tar) file to write to", type=str)
    parser.add_argument(
        "-d",
        "--dockerfile",
        type=str,
        default="",
        help="Name of the Dockerfile to target.",
    )
    parser.add_argument(
        "--build-arg",
        metavar="BUILD-ARG",
        dest="build_args",
        type=str,
        action="append",
        help="""Args to pass to Docker as build time variables. Each argument
                should be of the form VARIABLE=value. Can be specified multiple
                times.""",
    )
    parser.add_argument(
        "--file-build-arg",
        metavar="FILE-BUILD-ARG",
        dest="file_build_args",
        type=str,
        action="append",
        help="""File backed args to pass to Docker as build time variables.
                Each argument should be of the form VARIABLE=/path/to/file,
                where each file contains a single line value. Can be specified
                multiple times.""",
    )
    parser.add_argument(
        "context",
        type=str,
        help="Directory to be used as docker build context.",
    )
    return parser


def diff_hash_lists(out_file, context, fs):
    """
    If the expected.hash-list file exists, this function will output a list of
    hashes for the in-memory filesystem. It is intended to be used to figure out
    why a CI build produces a different tar to a local build:

    # Create an empty file to enable this functionality:
    touch ic-os/guestos/rootfs/expected.hash-list

    # Run Bazel to produce a hash listing for your local environment:
    bazel build //ic-os/guestos/envs/dev:rootfs-tree.tar --disk_cache= --remote_cache=

    # Copy hash listing produced by Bazel to expected.hash-list:
    cp bazel-bin/ic-os/guestos/envs/dev/rootfs-tree.tar.hash-list ic-os/guestos/rootfs/expected.hash-list

    # Commit and push expected.hash-list, then check CI logs to see the diff:
    git add ic-os/guestos/rootfs/expected.hash-list && git commit -m "Debugging (NOT TO BE MERGED)"
    """
    actual_hash_list = f"{out_file}.hash-list"
    with open(actual_hash_list, "w") as file:
        if len(context) == 0:
            return

        expected_hash_list = os.path.join(context, "expected.hash-list")
        if not os.path.isfile(expected_hash_list):
            return

        fs.write_hashes(file)
        file.flush()

        diff_cmd = ["diff", expected_hash_list, actual_hash_list]
        print(f"running: {diff_cmd}", file=sys.stderr)
        subprocess.run(diff_cmd)


def resolve_file_args(file_build_args: typing.List[str]) -> typing.List[str]:
    result = list()
    for arg in file_build_args:
        chunks = arg.split("=")
        if len(chunks) != 2:
            raise RuntimeError(f"File build arg '{arg}' is not valid")
        (name, path) = chunks

        with open(path) as f:
            value = f.readline().strip()
            result.append(f"{name}={value}")

    return result


def main():
    args = make_argparser().parse_args(sys.argv[1:])

    out_file = args.output
    dockerfile = args.dockerfile
    context = args.context
    build_args = list(args.build_args or [])

    # Bazel can't read files. (: Resolve them here, instead.
    resolved_file_args = resolve_file_args(args.file_build_args or [])
    build_args.extend(resolved_file_args)

    cmd_args = [v for arg in build_args for v in ("--build-arg", arg)]

    # Build the docker image.
    if not args.skip_pull:
        cmd_args.append("--pull")
    if any(
        [
            os.environ.get("CI_JOB_NAME", "").startswith("build-ic"),
            os.environ.get("CI_COMMIT_REF_PROTECTED", "false") == "true",
        ]
    ):
        cmd_args.append("--no-cache")

    cmd_args.append(context)

    image_hash = docker_build(cmd_args, dockerfile)

    # Extract and flatten all layers, build an in-memory pseudo filesystem
    # representing the docker image.
    fs = docker_extract_fs(image_hash)

    # Export the filesystem tree as a tar file.
    tar_fs(fs, open(out_file, "wb"))

    # Diff filesystem against an expected hash list if one is provided.
    diff_hash_lists(out_file, context, fs)

    print_artifact_info(out_file)


if __name__ == "__main__":
    main()
