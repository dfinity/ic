#!/usr/bin/env python3
import io
import json
import os
import shutil
import sys
import tarfile


def read_tar_contents(buffer):
    """Read tar file as map from filename -> content."""
    with tarfile.open(fileobj=buffer, mode="r|*") as tf:

        filemap = {}
        for member in tf:
            buf = member.tobuf()  # noqa - no idea why buf is here
            if member.type == tarfile.REGTYPE:
                filemap[member.name] = tf.extractfile(member).read()
            elif (member.type == tarfile.LNKTYPE) or (member.type == tarfile.SYMTYPE):
                filemap[member.name] = member.linkname[3:]
    return filemap


def get_layer_data(filemap):
    """Get the docker layer data from the filemap in correct order."""
    manifest = json.loads(filemap["manifest.json"])
    layers = manifest[0]["Layers"]

    out = []
    for layer in layers:
        if isinstance(filemap[layer], str):
            out.append(filemap[filemap[layer]])
        else:
            out.append(filemap[layer])

    return tuple(out)


target_dir = sys.argv[1]

filemap = read_tar_contents(sys.stdin.buffer)
layers = get_layer_data(filemap)

for layer in layers:
    tf = tarfile.open(fileobj=io.BytesIO(layer), mode="r")

    # Process all members in the tarfile. They are either ordinary
    # dirs/files/symlinks to be extracted, or they are "white-out" files:
    # These direct to delete certain underlying files from previous layer.
    for member in tf:
        basename = os.path.basename(member.path)
        dirname = os.path.dirname(member.path)
        if basename.startswith(".wh."):
            # This is a whiteout. Delete the file / directory.
            basename_target = basename[4:]
            target = os.path.join(target_dir, dirname, basename_target)
            if os.path.isdir(target):
                shutil.rmtree(target)
            elif os.path.exists(target):
                os.unlink(target)
        else:
            # Object to be created. Make sure that a previously existing
            # object is removed. This is important because the python tarfile
            # "extractall" method fails to overwrite symbolic links with
            # new links.
            target = os.path.join(target_dir, member.path)
            if os.path.lexists(target):
                if os.path.islink(target):
                    os.unlink(target)
                else:
                    was_dir = os.path.isdir(target)
                    should_be_dir = member.isdir()
                    if was_dir:
                        if not should_be_dir:
                            shutil.rmtree(target)
                    else:
                        if should_be_dir:
                            os.unlink(target)
            tf.extract(member, target_dir, numeric_owner=True)
            os.utime(target, (0, 0), follow_symlinks=False)
