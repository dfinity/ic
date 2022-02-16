#!/usr/bin/env python3
import argparse
import contextlib
import difflib
import os
import subprocess
import sys
import tempfile
import textwrap
import traceback


ARGUMENT_PARSER = argparse.ArgumentParser(
    description="""
Compares the working copy of Candid files passed via the command line against
HEAD. Fails if the changes are not compatible. E.g. if a record field type is
changed from int to text, then records that conformed to the old .did file will
not be understood by programs using the new .did file.

Example usage:

  cd "${ic_repo_root}"
  echo "changes" >> existing.did
  ./gitlab-ci/src/checks/candid_changes_are_backwards_compatible.py existing.did

Can be via pre-commit as follows:

  pre-commit run candid_changes_are_backwards_compatible

Note that pre-commit only sees staged changes. Therefore, one must git add
changed .did files before this test will notice one's changes.

To install pre-commit, follow the directions described at http://pre-commit.com.

Requires didc to be on PATH. Can be named didc-arm32, didc-linux64, didc-macos,
or just didc. Pre-compiled binaries can be downloaded at
https://github.com/dfinity/candid/releases.
""".strip()
)

ARGUMENT_PARSER.add_argument(
    "staged_file_paths",
    nargs="*",
    help="""
Path(s) relative to the repo root to .did files that have been staged and
should be checked for backwards compatibility.
""".strip(),
)

ARGUMENT_PARSER.add_argument(
    "--also-reverse",
    action="store_true",
    help="""
In addition to the usual `didc check after.did before.did`, also make sure that
`didc check before.did after.did` passes. This is useful when it is expected
that clients will "jump the gun", i.e. upgrade before servers. This is an
unusual (but not unheard of) use case.
""".strip(),
)


class Error(Exception):
    """Something bad happened."""


class SuspiciousDidcCheckOutput(Error):
    """didc check printed something suspicious to stdout and/or stderr."""

    def __init__(self, returncode, stdout, stderr):
        """Initialize."""
        self.returncode = returncode
        self.stdout = encode(stdout)
        self.stderr = encode(stderr)


def decode(s):
    return bytes.decode(s, "utf8")


def encode(b):
    return str.encode(b, "utf8")


def run(cmd):
    timeout_s = 5.0
    ch = subprocess.run(cmd, capture_output=True, timeout=timeout_s, check=True)
    return decode(ch.stdout), decode(ch.stderr)


def delete_files(paths):
    for p in paths:
        if p:
            os.remove(p)


def get_originals(staged_file_paths):
    originals = []
    for f in staged_file_paths:
        try:
            stdout, stderr = run(["git", "show", f"HEAD:./{f}"])
        except subprocess.CalledProcessError as e:
            is_new = any(
                phrase in e.stderr for phrase in [b"exists on disk, but not in 'HEAD'", b"does not exist in 'HEAD'"]
            )
            if not is_new:
                raise

            # There is no committed version of f.
            originals.append(None)
            continue

        parent, base = os.path.split(f)
        parent = parent or os.path.curdir
        descriptor, path = tempfile.mkstemp(prefix=f"{base}.original-", dir=parent)
        os.write(descriptor, encode(stdout))
        os.close(descriptor)
        originals.append(path)

    return originals


@contextlib.contextmanager
def originals(staged_file_paths):
    originals = get_originals(staged_file_paths)
    try:
        yield originals
    finally:
        delete_files(originals)


def find_didc_or_exit():
    for binary_name in ["didc-arm32", "didc-linux64", "didc-macos", "didc"]:
        try:
            stdout, stderr = run(["which", binary_name])
        except subprocess.CalledProcessError:
            continue

        print(f"Found didc: {binary_name}")
        print()
        return binary_name

    print(
        "didc not found. Please, install it.\n"
        "Pre-built binaries can be found here:\n"
        "https://github.com/dfinity/candid/releases"
    )
    sys.exit(1)


def print_run_fail(subprocess_called_process_error, *, prefix):
    e = subprocess_called_process_error

    if not isinstance(e, subprocess.CalledProcessError):
        print(f"  exception: {e}")
    print(f"  returncode: {e.returncode}")
    print("  stdout:")
    print(textwrap.indent(decode(e.stdout), prefix))
    print("  stderr:")
    print(textwrap.indent(decode(e.stderr), prefix))


def print_didc_check_failure(didc, before_path, after_path, e):
    prefix = " " * 4
    print(f"{didc} check found problem(s) in {after_path}:")
    print_run_fail(e, prefix=prefix)

    print("  diff:")
    sys.stdout.writelines(
        prefix + ln
        for ln in difflib.unified_diff(
            read_lines(before_path), read_lines(after_path), fromfile="before.did", tofile="after.did"
        )
    )


def read_lines(path):
    with open(path) as f:
        return list(f)


def didc_check(didc, server_did_file_path, client_did_file_path):
    stdout, stderr = run([didc, "check", server_did_file_path, client_did_file_path])
    sus = any((phrase in out.lower() for out in [stdout, stderr] for phrase in ["loss", "fix me"]))
    if sus:
        raise SuspiciousDidcCheckOutput(returncode=0, stdout=stdout, stderr=stderr)


def inspect_all_files(staged_file_paths, *, also_reverse):
    """
    Return true if no defects are found.

    Args:
    ----
      staged_file_paths: Same as command line argument(s).
      also_reverse: Same as --also-reverse.

    """
    didc = find_didc_or_exit()

    any_defective_files = False
    with originals(staged_file_paths) as paths_to_original_contents:
        # Compare .did files as they were before (at commit) vs. after changes.
        for before, after in zip(paths_to_original_contents, staged_file_paths):
            # Skip when there is no previous version to comapre to (the staged file is new).
            if before is None:
                continue

            try:
                didc_check(didc, after, before)
                if also_reverse:
                    didc_check(didc, before, after)
            except (subprocess.CalledProcessError, SuspiciousDidcCheckOutput) as e:
                any_defective_files = True
                print_didc_check_failure(didc, before, after, e)
                print()

    return any_defective_files


def main(argv):
    args = ARGUMENT_PARSER.parse_args()

    print("Files to be inspected:")
    for f in args.staged_file_paths:
        print(f"  - {f}")
    print()

    try:
        any_defective_files = inspect_all_files(args.staged_file_paths, also_reverse=args.also_reverse)
    except subprocess.CalledProcessError as e:
        traceback.print_exc()
        print()
        print("An internal error occurred:")
        print_run_fail(e, prefix=" " * 4)
        print()
        sys.exit(1)

    if any_defective_files:
        print(
            "Oh noez! Something has gone wrong.\n"
            "(See earlier output for diagnostics.)\n"
            "To reproduce locally, run this command:\n"
            "  pre-commit run candid_changes_are_backwards_compatible"
        )
        sys.exit(1)
    else:
        print("Success!")


if __name__ == "__main__":
    main(sys.argv[1:])
