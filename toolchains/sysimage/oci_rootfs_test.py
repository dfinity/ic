import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from toolchains.sysimage.oci_rootfs import flatten


def layer(entries) -> bytes:
    """A gzipped layer tar from (name, type, payload) entries."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 12345
            info.uname = "someone"
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            elif kind == "file":
                data = payload.encode()
                info.size = len(data)
                info.mode = 0o644
                info.uid, info.gid = 7, 8
                tar.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tar.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tar.addfile(info)
    return gzip.compress(buffer.getvalue(), mtime=0)


def write_layout(directory: Path, layers, env):
    blobs = directory / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def blob(data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return "sha256:" + digest

    config = json.dumps({"config": {"Env": env}}).encode()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": blob(config)},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blob(data)} for data in layers
            ],
        }
    ).encode()
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": blob(manifest),
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        ],
    }
    (directory / "index.json").write_text(json.dumps(index))


class FlattenTest(unittest.TestCase):
    def flatten(self, layers, env=None):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        write_layout(tmp / "layout", layers, env or ["PATH=/bin"])
        flatten(tmp / "layout", "linux/amd64", tmp / "rootfs.tar", tmp / "env.json")
        members = {}
        with tarfile.open(tmp / "rootfs.tar") as tar:
            names = tar.getnames()
            for member in tar.getmembers():
                data = tar.extractfile(member).read().decode() if member.isreg() else None
                members[member.name] = (member, data)
        return names, members, json.loads((tmp / "env.json").read_text())

    def test_layers_whiteouts_and_normalization(self):
        names, members, env = self.flatten(
            [
                layer(
                    [
                        ("./etc", "dir", None),
                        ("./etc/a", "file", "a1"),
                        ("./etc/b", "file", "b"),
                        ("./opt", "dir", None),
                        ("./opt/x", "file", "x"),
                        ("./opt/sub", "dir", None),
                        ("./opt/sub/y", "file", "y"),
                        ("./var", "dir", None),
                        ("./var/old", "file", "old"),
                        ("./lib", "symlink", "usr/lib"),
                    ]
                ),
                layer(
                    [
                        ("etc/a", "file", "a2"),  # overwrite
                        ("etc/.wh.b", "file", ""),  # whiteout
                        ("opt/.wh..wh..opq", "file", ""),  # opaque: hide opt/*
                        ("opt/new", "file", "new"),
                        ("var", "file", "not a dir"),  # replaces the directory
                    ]
                ),
            ],
            env=["PATH=/usr/bin", "SOURCE_DATE_EPOCH=0"],
        )
        self.assertEqual(names, sorted(names))
        self.assertEqual(names, ["etc", "etc/a", "lib", "opt", "opt/new", "var"])
        self.assertEqual(members["etc/a"][1], "a2")
        self.assertEqual(members["var"][1], "not a dir")
        self.assertEqual(members["lib"][0].linkname, "usr/lib")
        self.assertEqual((members["etc/a"][0].uid, members["etc/a"][0].gid), (7, 8))
        for member, _ in members.values():
            self.assertEqual((member.mtime, member.uname, member.gname), (0, "", ""))
        self.assertEqual(env, ["PATH=/usr/bin", "SOURCE_DATE_EPOCH=0"])

    def test_hard_link_before_its_target_in_name_order(self):
        names, members, _ = self.flatten(
            [layer([("z", "file", "data"), ("a", "hardlink", "z"), ("m", "hardlink", "z")])]
        )
        self.assertEqual(names, ["a", "m", "z"])
        self.assertTrue(members["a"][0].isreg())
        self.assertEqual(members["a"][1], "data")
        self.assertTrue(members["m"][0].islnk() and members["m"][0].linkname == "a")
        self.assertTrue(members["z"][0].islnk() and members["z"][0].linkname == "a")

    def test_whiteout_of_a_directory_hides_its_contents(self):
        names, _, _ = self.flatten(
            [layer([("d", "dir", None), ("d/f", "file", "f"), ("e", "file", "e")]), layer([(".wh.d", "file", "")])]
        )
        self.assertEqual(names, ["e"])


if __name__ == "__main__":
    unittest.main()
