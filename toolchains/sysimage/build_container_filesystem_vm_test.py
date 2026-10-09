import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from toolchains.sysimage.build_container_filesystem_vm import (
    copy_commands,
    export_filesystem,
    generate_steps,
    has_entry,
    read_result,
)
from toolchains.sysimage.dockerfile import Copy, Plan, Run


class CopyTest(unittest.TestCase):
    """Runs the generated COPY commands on a temporary context and root."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        # Like tmpdir_wrapper.sh: the test's directory can be setgid (e.g. on the
        # dind-large CI runners), which the directories below would inherit.
        os.chmod(self.tmp, 0o700)
        self.context = self.tmp / "ctx"
        self.root = self.tmp / "root"
        self.context.mkdir()
        self.root.mkdir()

    def write(self, path: Path, text: str, mode: int = 0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)

    def copy(self, step: Copy):
        script = "set -e\n" + "\n".join(copy_commands(step, context=str(self.context), root=str(self.root)))
        subprocess.run(["sh", "-c", script], check=True)

    def test_directory_is_merged_into_the_destination(self):
        self.write(self.context / "etc/a", "a", 0o640)
        self.write(self.context / "etc/sub/b", "b", 0o755)
        self.write(self.root / "etc/old", "old")
        self.copy(Copy(sources=["etc"], destination="/etc"))
        self.assertEqual((self.root / "etc/a").read_text(), "a")
        self.assertEqual((self.root / "etc/a").stat().st_mode & 0o7777, 0o640)
        self.assertEqual((self.root / "etc/sub/b").stat().st_mode & 0o7777, 0o755)
        self.assertEqual((self.root / "etc/old").read_text(), "old")

    def test_file_to_a_new_path(self):
        self.write(self.context / "f", "f")
        self.copy(Copy(sources=["f"], destination="/x/y"))
        self.assertEqual((self.root / "x/y").read_text(), "f")

    def test_file_with_chmod_onto_an_existing_directory(self):
        self.write(self.context / "f", "f")
        (self.root / "d").mkdir(mode=0o755)
        self.copy(Copy(sources=["f"], destination="/d", chmod="600"))
        self.assertEqual((self.root / "d/f").stat().st_mode & 0o7777, 0o600)
        self.assertEqual((self.root / "d").stat().st_mode & 0o7777, 0o755)

    def test_multiple_sources_go_into_the_directory(self):
        self.write(self.context / "a", "a")
        self.write(self.context / "b", "b")
        self.copy(Copy(sources=["a", "b"], destination="/dir"))
        self.assertEqual(sorted(os.listdir(self.root / "dir")), ["a", "b"])

    def test_replacing_a_hard_link_leaves_the_other_name_alone(self):
        self.write(self.context / "f", "new")
        self.write(self.root / "x", "old")
        os.link(self.root / "x", self.root / "y")
        self.copy(Copy(sources=["f"], destination="/x"))
        self.assertEqual((self.root / "x").read_text(), "new")
        self.assertEqual((self.root / "y").read_text(), "old")


class GenerateStepsTest(unittest.TestCase):
    def test_run_steps_get_the_image_env_and_their_args(self):
        build_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        steps = generate_steps(
            Plan(base_image="base", steps=[Run(command="echo 'hi there'", args={"A": "x y"}), Copy(["f"], "/f")]),
            ["PATH=/bin", "Q=it's"],
            build_dir,
        )
        self.assertEqual((build_dir / "run/0001").read_text(), "echo 'hi there'")
        self.assertIn("env -i PATH=/bin 'Q=it'\"'\"'s' 'A=x y' /bin/sh -c", steps)
        self.assertIn(">>> step 2/2: COPY f /f", steps)
        self.assertFalse((build_dir / "run/0002").exists())


class ExportTest(unittest.TestCase):
    def tar(self, entries) -> Path:
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "vm.tar"
        with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
            for name, kind, link in entries:
                info = tarfile.TarInfo(name)
                info.mtime = 1234
                info.uname = info.gname = "root"
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                elif kind == "file":
                    info.size = 4
                    tar.addfile(info, io.BytesIO(b"data"))
                else:
                    info.type = tarfile.LNKTYPE
                    info.linkname = link
                    tar.addfile(info)
        return path

    def test_normalizes_like_the_podman_export(self):
        source = self.tar(
            [
                ("./", "dir", None),
                ("./etc/", "dir", None),
                ("./etc/a", "file", None),
                ("./etc/b", "link", "./etc/a"),
                ("./run/", "dir", None),
                ("./run/x", "file", None),
            ]
        )
        output = source.with_name("out.tar")
        export_filesystem(source, str(output))
        with tarfile.open(output) as tar:
            members = tar.getmembers()
        # Like the podman export: run/'s contents are dropped, the directory is kept.
        self.assertEqual([m.name for m in members], ["etc", "etc/a", "etc/b", "run"])
        self.assertEqual(members[2].linkname, "etc/a")
        for member in members:
            self.assertEqual((member.mtime, member.uname, member.gname), (0, "", ""))

    def test_hard_link_into_run_is_an_error(self):
        source = self.tar([("./run/", "dir", None), ("./run/x", "file", None), ("./y", "link", "./run/x")])
        with self.assertRaises(RuntimeError):
            export_filesystem(source, str(source.with_name("out.tar")))

    def test_has_entry(self):
        source = self.tar([("./lost+found/", "dir", None), ("./etc/", "dir", None)])
        self.assertTrue(has_entry(source, "lost+found"))
        self.assertFalse(has_entry(source, "found"))


class ReadResultTest(unittest.TestCase):
    def status_disk(self, data: bytes) -> Path:
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "status.img"
        with open(path, "wb") as f:
            f.write(data)
            f.truncate(1 << 20)
        return path

    def test_result(self):
        self.assertEqual(read_result(self.status_disk(b"ICOS-BUILD-RESULT: 0\n")), 0)
        self.assertEqual(read_result(self.status_disk(b"ICOS-BUILD-RESULT: 32\n")), 32)

    def test_no_or_partial_result(self):
        self.assertIsNone(read_result(self.status_disk(b"")))
        self.assertIsNone(read_result(self.status_disk(b"ICOS-BUILD-RESULT: 1")))


if __name__ == "__main__":
    unittest.main()
