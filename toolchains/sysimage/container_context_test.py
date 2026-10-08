import os
import tempfile
import unittest
from pathlib import Path

from toolchains.sysimage.container_context import arrange_context, resolve_file_args


class ArrangeContextTest(unittest.TestCase):
    def test_modes_depend_only_on_the_executable_bit(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        sources = tmp / "src"
        sources.mkdir()
        for name, mode in [("ro", 0o444), ("rx", 0o555), ("rw", 0o600), ("rwx", 0o700)]:
            (sources / name).write_text(name)
            (sources / name).chmod(mode)
        context = tmp / "ctx"
        context.mkdir()
        old_umask = os.umask(0o077)
        try:
            arrange_context(
                str(context),
                [str(sources / "ro"), str(sources / "rx")],
                [f"{sources / 'rw'}:/etc/a/b/rw", f"{sources / 'rwx'}:/opt/bin/rwx"],
            )
        finally:
            os.umask(old_umask)

        def mode(path):
            return (context / path).stat().st_mode & 0o7777

        self.assertEqual(mode("ro"), 0o644)
        self.assertEqual(mode("rx"), 0o755)
        self.assertEqual(mode("etc/a/b/rw"), 0o644)
        self.assertEqual(mode("opt/bin/rwx"), 0o755)
        # Created directories don't depend on the umask.
        for directory in ["etc", "etc/a", "etc/a/b", "opt", "opt/bin"]:
            self.assertEqual(mode(directory), 0o755, directory)


class ResolveFileArgsTest(unittest.TestCase):
    def test_first_line_of_the_file(self):
        context = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (context / "docker-base").write_text("base@sha256:1\nignored\n")
        self.assertEqual(resolve_file_args(str(context), ["BASE_IMAGE=docker-base"]), ["BASE_IMAGE=base@sha256:1"])

    def test_invalid_arg(self):
        with self.assertRaises(RuntimeError):
            resolve_file_args("/", ["A=b=c"])


if __name__ == "__main__":
    unittest.main()
