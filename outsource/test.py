#!/usr/bin/env python3
import pathlib
import subprocess
import tempfile
import unittest

import remote
import shell_safe


class TestCaseBase(unittest.TestCase):
    """Extend the basic TestCase with file assertions."""

    def assertIsFile(self, path):
        """Assert that the path exists and is a file."""
        if not pathlib.Path(path).resolve().is_file():
            raise AssertionError("File does not exist: %s" % str(path))

    def assertNotIsFile(self, path):
        """Assert that the path does not exist or is not a file."""
        if pathlib.Path(path).resolve().is_file():
            raise AssertionError("File exists: %s" % str(path))

    def assertIsDir(self, path):
        """Assert that the path does not exist or is not a directory."""
        if not pathlib.Path(path).resolve().is_dir():
            raise AssertionError("Directory does not exist: %s" % str(path))

    def assertNotIsDir(self, path):
        """Assert that the path does not exist or is not a directory."""
        if pathlib.Path(path).resolve().is_dir():
            raise AssertionError("Directory exists: %s" % str(path))


class TestRemote(TestCaseBase):
    """Test the correct behavior of the 'remote' script."""

    def test_sanitized_argv(self):
        """Ensure arguments are sanitized properly."""
        self.assertEqual(remote.sanitized_argv([]), [])
        self.assertEqual(remote.sanitized_argv(["echo", "hello"]), ["--", "echo", "hello"])
        self.assertEqual(
            remote.sanitized_argv(["-v", "hello", "world", "--foo"]),
            ["-v", "--", "hello", "world", "--foo"],
        )

    def test_shell_safe_encode_decode_id(self):
        """Ensure shell-safe encoding roundtrip is the identity."""

        def roundtrip(obj):
            enc = shell_safe.encode(obj)
            dec = shell_safe.decode(enc)
            return dec

        test_cases = [["echo", "hello"], "foo", "utf-8 yay? 😃"]

        [self.assertEqual(obj, roundtrip(obj)) for obj in test_cases]

    def test_rsync_to_builder(self):
        """Ensure files are correctly synced to the remote."""
        with tempfile.TemporaryDirectory() as tmpdirname:

            source = pathlib.Path(tmpdirname) / "source"
            source.mkdir()

            subprocess.check_call(["git", "init"], cwd=source)

            # a .gitignore similar to the one we use currently
            with open(source / ".gitignore", "w") as f:
                f.write(".*\n!.gitignore")
            with open(source / "file", "w") as f:
                f.write("")

            (source / "dir").mkdir()
            with open(source / "dir" / ".gitignore", "w") as f:
                f.write(".*\n!.gitignore")

            target = pathlib.Path(tmpdirname) / "target"
            target.mkdir()
            with open(target / "does-not-exist", "w") as f:
                f.write("")

            remote.rsync_to_builder(str(source), str(target))

            self.assertIsDir(source / "dir")

            # The current behavior of rsync
            self.assertNotIsDir(target / ".git")
            self.assertIsFile(target / ".gitignore")
            self.assertIsFile(target / "file")
            self.assertIsFile(target / "dir" / ".gitignore")
            self.assertNotIsFile(target / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
