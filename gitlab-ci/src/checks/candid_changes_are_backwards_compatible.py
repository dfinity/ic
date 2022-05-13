#!/usr/bin/env python3
import argparse
import contextlib
import difflib
import os
import pprint
import subprocess
import sys
import tempfile
import textwrap
import traceback


ARGUMENT_PARSER = argparse.ArgumentParser(
    description="""
Compares the working copy of Candid file(s) passed via the command line against
their original version(s). Fails if the changes are not compatible.

There are two modes of operation, which determine whence the originals come. By
default, originals come from HEAD. Alternatively, if there is an environment
variable named CI_MERGE_REQUEST_TARGET_BRANCH_NAME (available in the Gitlab CI
execution environment), then the originals are drawn from the following git
commit:

  git merge-base $(echo $CI_MERGE_REQUEST_TARGET_BRANCH_NAME) HEAD

A particularly egregious example of an incompatible change would be the removal
of a method, because well-behaved clients will start seeing rejections from the
server.

Example usage:

  cd "${ic_repo_root}"
  echo "changes" >> existing.did
  ./gitlab-ci/src/checks/candid_changes_are_backwards_compatible.py existing.did

Can be run via pre-commit as follows:

  pre-commit run candid_changes_are_backwards_compatible

Note that when run via pre-commit, only staged changes are visible. Therefore,
one must git add changed .did files before this test will notice one's changes.

To install pre-commit, follow the directions described at http://pre-commit.com.

TODO: Support pre-commit's --from-ref (and --to-ref) flags. These cause
environment variables to be set. Possible environment variables of interest:
  - PRE_COMMIT
  - PRE_COMMIT_FROM_REF
  - PRE_COMMIT_ORIGIN
  - PRE_COMMIT_SOURCE
  - PRE_COMMIT_TO_REF

Requires didc to be on PATH. Can be named didc-arm32, didc-linux64, didc-macos,
or just didc. Pre-compiled binaries can be downloaded at
https://github.com/dfinity/candid/releases.

Behavior affected by a couple of environment variables:

1. CI_MERGE_REQUEST_TARGET_BRANCH_NAME: Described above.
2. CI_MERGE_REQUEST_TITLE: See --also-reverse.
""".strip()
)

ARGUMENT_PARSER.add_argument(
    "candid_file_paths",
    nargs="*",
    help="""
Path(s) to the working copy of .did files that are to be inspected for
compatibility when compared with their originals. When run "conventionally"
(i.e. outside Gitlab CI), the original version comes from HEAD. Otherwise,
originals sourced based on the CI_MERGE_REQUEST_TARGET_BRANCH_NAME environment
variable (as described in the main help string).
""".strip(),
)

ARGUMENT_PARSER.add_argument(
    "--also-reverse",
    action="store_true",
    help="""
In addition to the usual `didc check after.did before.did`, also make sure that
`didc check before.did after.did` passes. This is useful when it is expected
that clients will "jump the gun", i.e. upgrade before servers. This is an
unusual (but not unheard of) use case. This can be disabled if the
CI_MERGE_REQUEST_TITLE environment variable contains "[override-also-reverse]".
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


def get_originals(candid_file_paths, *, diff_base):
    originals = []
    for f in candid_file_paths:
        try:
            stdout, stderr = run(["git", "show", f"{diff_base}:./{f}"])
        except subprocess.CalledProcessError as e:
            is_new = any(phrase in e.stderr for phrase in [b"exists on disk, but not in ", b"does not exist in "])
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
def originals(candid_file_paths, *, diff_base):
    originals = get_originals(candid_file_paths, diff_base=diff_base)
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
    short_didc = os.path.split(didc)[1]
    print(f"{short_didc} check found problem(s) in {after_path}:")
    print_run_fail(e, prefix=prefix)

    print("  diff:")
    sys.stdout.writelines(
        prefix + ln
        for ln in difflib.unified_diff(
            read_lines(before_path), read_lines(after_path), fromfile="before.did", tofile="after.did"
        )
    )

    print(
        "  Tip:\n"
        "    If the only thing you did was add a method, add [override-also-reverse]\n"
        "    to the title of your merge request."
    )


def read_lines(path):
    with open(path) as f:
        return list(f)


def didc_check(didc, server_did_file_path, client_did_file_path):
    stdout, stderr = run([didc, "check", server_did_file_path, client_did_file_path])
    sus = any((phrase in out.lower() for out in [stdout, stderr] for phrase in ["loss", "fix me"]))
    if sus:
        raise SuspiciousDidcCheckOutput(returncode=0, stdout=stdout, stderr=stderr)


def inspect_all_files(candid_file_paths, *, also_reverse, diff_base):
    """
    Return true if no defects are found.

    Args:
    ----
      candid_file_paths: Same meaning as candid_file_paths command line argument(s).
      also_reverse: Same meaning as --also-reverse.
      diff_base: Where to get copies of the originals. E.g. "HEAD", or some other git commit hash.

    """
    didc = find_didc_or_exit()

    any_defective_files = False
    with originals(candid_file_paths, diff_base=diff_base) as paths_to_original_contents:
        # Compare .did files as they were before (at commit) vs. after changes.
        for before, after in zip(paths_to_original_contents, candid_file_paths):
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


def get_diff_base():
    try:
        target_branch = os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]
    except KeyError:
        print('Looks like we are running "conventionally", i.e. not in Gitlab CI.')
        return "HEAD"

    stdout, _stderr = run(["git", "fetch", "origin", target_branch])
    stdout, _stderr = run(["git", "merge-base", f"origin/{target_branch}", "HEAD"])
    diff_base = stdout.strip()
    print(f"It appears we are in Gitlab CI. {target_branch = } {diff_base = }")
    return diff_base


def main(argv):
    print("A selection of environment variables:")
    pprint.pprint(sorted((k, v) for k, v in os.environ.items() if "commit" in k.lower()))
    print()

    args = ARGUMENT_PARSER.parse_args()

    print("Files to be inspected:")
    for f in args.candid_file_paths:
        print(f"  - {f}")
    print()

    diff_base = get_diff_base()
    print()

    override = "[override-also-reverse]" in os.environ.get("CI_MERGE_REQUEST_TITLE", "")
    also_reverse = args.also_reverse and not override

    try:
        any_defective_files = inspect_all_files(args.candid_file_paths, also_reverse=also_reverse, diff_base=diff_base)
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
