#!/usr/bin/env python3
#
# Flatten an OCI image (an OCI image layout directory, as fetched by rules_oci's
# oci_pull) into a single root filesystem tar, without a container engine.
#
# The layers are applied in order, honouring OCI whiteouts (`.wh.<name>` and
# the opaque marker `.wh..wh..opq`). The output lists the entries sorted by
# name, with the owners, modes and link targets of the image, mtime 0 and no
# user/group names or extended attributes, which is what the IC-OS image builds
# keep of a container filesystem (see build_container_filesystem_tar.py).
#
# The image config's environment (`Env`, e.g. PATH and SOURCE_DATE_EPOCH) is
# written as JSON to --env-output, for running the Dockerfile steps on top.
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT = ".wh..wh..opq"

MEDIA_TYPES_GZIP = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
MEDIA_TYPES_TAR = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar"}
MEDIA_TYPES_INDEX = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


def normalize(name: str) -> str:
    """Return the canonical form of a tar member name: relative, no `./` prefix, no trailing slash."""
    name = name.lstrip("/")
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def is_under(name: str, directory: str) -> bool:
    return name.startswith(directory + "/")


@dataclass(eq=False)
class Entry:
    layer: int  # index into the list of uncompressed layer tars
    info: tarfile.TarInfo
    # The entry holding the data and metadata: the entry itself, or for a hard
    # link the entry it linked to when its layer was applied. Like an inode in
    # overlayfs, it stays with the link when a later layer replaces its target.
    inode: Optional["Entry"] = None

    def __post_init__(self):
        if self.inode is None:
            self.inode = self


class Layout:
    """An OCI image layout directory."""

    def __init__(self, path: Path):
        self.path = path

    def blob(self, digest: str) -> Path:
        algorithm, value = digest.split(":", 1)
        return self.path / "blobs" / algorithm / value

    def read_json(self, digest: str) -> dict:
        return json.loads(self.blob(digest).read_text())

    def manifest(self, platform: str) -> dict:
        os_name, architecture = platform.split("/")
        index = json.loads((self.path / "index.json").read_text())
        candidates = index["manifests"]
        while True:
            if len(candidates) == 1:
                descriptor = candidates[0]
            else:
                matching = [
                    m
                    for m in candidates
                    if m.get("platform", {}).get("os") == os_name
                    and m.get("platform", {}).get("architecture") == architecture
                ]
                if len(matching) != 1:
                    raise RuntimeError(f"expected exactly one {platform} manifest, found {len(matching)}")
                descriptor = matching[0]
            document = self.read_json(descriptor["digest"])
            if document.get("mediaType", descriptor.get("mediaType")) in MEDIA_TYPES_INDEX:
                candidates = document["manifests"]
                continue
            return document


def uncompress_layer(layout: Layout, descriptor: dict, destination: Path):
    media_type = descriptor["mediaType"]
    source = layout.blob(descriptor["digest"])
    if media_type in MEDIA_TYPES_GZIP:
        with gzip.open(source, "rb") as src, open(destination, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    elif media_type in MEDIA_TYPES_TAR:
        shutil.copyfile(source, destination)
    else:
        # E.g. zstd-compressed layers, which would need a (declared) zstd tool.
        raise RuntimeError(f"unsupported layer media type {media_type}")


def apply_layer(entries: Dict[str, Entry], layer_index: int, layer: tarfile.TarFile):
    members = layer.getmembers()

    # Whiteouts only hide entries of the lower layers, so apply them first.
    for member in members:
        name = normalize(member.name)
        parent, base = os.path.split(name)
        if base == OPAQUE_WHITEOUT:
            # Hide everything the lower layers have in this directory.
            for other in [n for n in entries if not parent or is_under(n, parent)]:
                del entries[other]
        elif base.startswith(WHITEOUT_PREFIX):
            hidden = os.path.join(parent, base[len(WHITEOUT_PREFIX) :])
            for other in [n for n in entries if n == hidden or is_under(n, hidden)]:
                del entries[other]

    for member in members:
        name = normalize(member.name)
        base = os.path.basename(name)
        if not name or base.startswith(WHITEOUT_PREFIX):
            continue
        previous = entries.get(name)
        if previous is not None and previous.info.isdir() and not member.isdir():
            # A non-directory replaces a directory together with its contents.
            for other in [n for n in entries if is_under(n, name)]:
                del entries[other]
        if member.islnk():
            target = entries.get(normalize(member.linkname))
            if target is None:
                raise RuntimeError(f"{name} is a hard link to {member.linkname}, which isn't in the image")
            entries[name] = Entry(layer_index, member, target.inode)
        else:
            entries[name] = Entry(layer_index, member)


def write_rootfs(entries: Dict[str, Entry], layers: List[tarfile.TarFile], output: Path):
    # The first name (in name order) of each inode is written as the file, and
    # the other names as hard links to it.
    written_as: Dict[int, str] = {}
    with tarfile.open(output, "w", format=tarfile.GNU_FORMAT) as out:
        for name in sorted(entries):
            inode = entries[name].inode
            src = inode.info
            new = tarfile.TarInfo(name)
            new.mode = src.mode
            new.uid = src.uid
            new.gid = src.gid
            new.mtime = 0
            new.uname = ""
            new.gname = ""
            if id(inode) in written_as:
                new.type = tarfile.LNKTYPE
                new.linkname = written_as[id(inode)]
                out.addfile(new)
                continue
            written_as[id(inode)] = name
            if src.isreg():
                new.type = tarfile.REGTYPE
                new.size = src.size
                out.addfile(new, layers[inode.layer].extractfile(src))
            else:
                new.type = src.type
                new.linkname = src.linkname
                new.devmajor = src.devmajor
                new.devminor = src.devminor
                out.addfile(new)


def flatten(layout_dir: Path, platform: str, output: Path, env_output: Path):
    """Flatten the image in layout_dir into the root filesystem tar output, and its Env into env_output."""
    layout = Layout(layout_dir)
    manifest = layout.manifest(platform)
    config = layout.read_json(manifest["config"]["digest"])
    env_output.write_text(json.dumps(config.get("config", {}).get("Env") or [], indent=1) + "\n")

    with tempfile.TemporaryDirectory() as tmp:
        entries: Dict[str, Entry] = {}
        layers: List[tarfile.TarFile] = []
        try:
            for index, descriptor in enumerate(manifest["layers"]):
                path = Path(tmp) / f"layer{index}.tar"
                uncompress_layer(layout, descriptor, path)
                layer = tarfile.open(path, "r:")
                layers.append(layer)
                apply_layer(entries, index, layer)
            write_rootfs(entries, layers, output)
        finally:
            for layer in layers:
                layer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", required=True, type=Path, help="OCI image layout directory")
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--output", required=True, type=Path, help="Root filesystem tar to write")
    parser.add_argument("--env-output", required=True, type=Path, help="JSON list of the image's environment")
    args = parser.parse_args()
    flatten(args.layout, args.platform, args.output, args.env_output)


if __name__ == "__main__":
    main()
