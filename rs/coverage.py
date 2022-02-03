#!/usr/bin/env nix-shell
#! nix-shell -i python3 shell.nix
# see go/code-coverage for documentation and instructions.
"""Generate a coverage report for the workspace."""
import argparse
import os
import subprocess
import sys
import tempfile
from typing import Optional

import toml

# These tests are excluded for one of the following reasons:
# - Runtime unbearably long
# - Runs to slow to success (i.e. use real time source and times out under kcov)
# - Expect to be run from particlar working directory
# - Have to be compiled to WASM but kcov can only instrument native code
# TODO: Implement --no-default-excludes to allow running these tests if desired.
excluded_packages = [
    "test",  # Long runtime
    "ic-nns-integration-tests",  # Hangs up, likely run from wrong working directory
    "ic-nns-handler-root",
    "ic-rosetta-api",  # Run from wrong working directory
    "ic-replica-tests",  # Runs too slow
    "ic-wasm-utils",  # Can not be compiled natively
    "registry-canister",  # Run from wrong directory
    "rust-canister-tests",  # Runs too slow
    "ledger-canister",  # Runs too slow
    "pmap",  # Can not be compiled natively
    "dfn_core",  # Can not be compiled natively
]


def eprint(*args, **kwargs):
    """Shorthand to write to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def check_executables_and_get_workdir():
    """
    Check that the necessary executables are installed on the system.

    Returns the git base directory too.
    """
    # Check kcov
    subprocess.run(["kcov", "--version"], capture_output=True, check=True)
    # Check cargo with
    subprocess.run(["cargo", "with", "--help"], capture_output=True, check=True)

    # Check git and return the base directory
    directory = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=True)
    if directory.returncode != 0:
        return None
    else:
        return directory.stdout.decode("utf-8").rstrip("\n")


def get_paths_from_toml(base_dir):
    """Return workspace member paths."""
    parsed_toml = toml.load(os.path.join(base_dir, "rs/Cargo.toml"))

    if "workspace" not in parsed_toml or "members" not in parsed_toml["workspace"]:
        raise Exception("Cargo.toml does not represent a workspace")

    paths = list(
        map(
            lambda path: os.path.join(base_dir, "rs", path),
            parsed_toml["workspace"]["members"],
        )
    )
    return paths


def get_crate_name_and_version_from_path(crate_path):
    """Return name of the crate from the path."""
    parsed_toml = toml.load(os.path.join(crate_path, "Cargo.toml"))

    if "package" not in parsed_toml:
        raise Exception("Cargo.toml is invalid")
    if "name" not in parsed_toml["package"] or "version" not in parsed_toml["package"]:
        raise Exception("Cargo.toml is invalid")

    return (parsed_toml["package"]["name"], parsed_toml["package"]["version"])


def handle_multiple_tests(base_dir, crate_path, pkg, error_msg):
    """Handle the case where there are multiple tests tu run."""
    assert len(error_msg) >= 2
    error_msg = error_msg.split("\n")
    if error_msg[1] == "No tests available.":

        return []
    assert error_msg[1] == "Available tests:"
    pkg_exes = list(map(lambda pkg_exe: pkg_exe.lstrip(" "), error_msg[2:-3]))

    print("Running separate test binaries %s" % pkg_exes)
    tempdirs = []
    for pkg_exe in pkg_exes:
        result = run_coverage_test(base_dir, crate_path, "test", pkg, pkg_exe)
        if not isinstance(result, str):
            tempdirs.append(result)

    return tempdirs


def cover_crate(base_dir, crate_path, excludes=None, includes=None, jobs: Optional[int] = None):
    """
    Cover a create specified by its path.

    If includes is specified, the crate must be in this list.
    If excludes is specified, the crate must not be on this list
    """
    (pkg, _) = get_crate_name_and_version_from_path(crate_path)

    # Apply the filter
    if excludes and pkg in excludes:
        return []
    if includes and pkg not in includes:
        return []

    cmd = ["cargo", "test", "--no-run", "-p", pkg]
    if jobs is not None:
        cmd += ["-j", str(jobs)]

    # build the tests first with stderr enabled so users can see progress
    print(f"Compiling testsuite for {pkg}")
    subprocess.run(cmd, cwd=os.path.join(base_dir, "rs"), check=True)

    # Run the coverage
    tempdirs = []

    # Run --lib tests
    print("Running lib tests for crate %s" % pkg)
    lib_test = run_coverage_test(base_dir, crate_path, "lib", pkg, "")
    if not isinstance(lib_test, str):
        tempdirs.append(lib_test)

    # We run --tests here without an argument.
    # This should work, if there is only one file in the tests directory.
    #
    print("Running test binaries for crate %s" % pkg)
    tests = run_coverage_test(base_dir, crate_path, "test", pkg, "")
    if not isinstance(tests, str):
        tempdirs.append(tests)
    else:
        # Othwise parse the error message and try to get
        tempdirs += handle_multiple_tests(base_dir, crate_path, pkg, tests)

    return tempdirs


def run_coverage_test(base_dir, crate_path, ty, pkg, pkg_exe):
    """
    Run a coverage test.

    Returns the temporary directory handle and path, if test was successfull.
    Returns output of stderr otherwise
    """
    wd = os.path.join(base_dir, "rs")
    tempdir = tempfile.TemporaryDirectory()
    out_path = os.path.join(tempdir.name, pkg + "-" + ty)
    # Run the subprocess
    # Example:
    # cargo with "kcov {args} {bin}" -- test -p ic-consensus --lib ic-consensus -- --include-pattern=/rs/consensus/ --exclude-pattern=test /tmp/cov1

    try:
        cmd = [
            "cargo",
            "with",
            "kcov {args} {bin}",
            "--",
            "test",
            "-p",
            pkg,
            "--" + ty,
            pkg_exe,
            "--",
            "--include-pattern=" + crate_path,
            # TODO: Allow for unfiltered coverage results as an extra option
            # "--include-pattern=" + wd,
            "--exclude-pattern=test",
            out_path,
        ]
        # Remove pkg_exe from list, if it was left empty
        if not pkg_exe:
            del cmd[8]

        test = subprocess.run(cmd, cwd=wd, stderr=subprocess.PIPE)

        if test.returncode != 0:
            tempdir.cleanup()
            return test.stderr.decode("utf-8")
        else:
            return (tempdir, out_path)
    except KeyboardInterrupt:
        sys.exit(-1)


def kcov_merge(out_dir, in_dirs):
    """Merge a list of coverage results into a single result."""
    cmd = ["kcov", "--merge", out_dir] + in_dirs
    subprocess.run(cmd)


def _get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-path",
        help="set the path of the repository manually",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="output path of the coverage result (defaults to 'target/cov')",
    )
    parser.add_argument(
        "-p",
        "--package",
        help="only generate coverage for these packages",
        action="append",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        help="exclude a package from coverage generation",
        action="append",
    )
    parser.add_argument("-j", "--jobs", help="--jobs argument to pass to cargo", type=int)

    return parser.parse_args()


if __name__ == "__main__":
    args = _get_args()

    # Check executables and get a base directory
    base_dir = check_executables_and_get_workdir()
    if args.repo_path:
        base_dir = args.repo_path
    if not base_dir:
        eprint("Repo not found. Must execute script from within repo or provice --repo-path.")
        sys.exit(-1)

    if args.exclude:
        excluded_packages += args.exclude

    crate_paths = get_paths_from_toml(base_dir)

    # Execute the coverage tests
    tempdirs = []
    for crate_path in crate_paths:
        results = cover_crate(base_dir, crate_path, excludes=excluded_packages, includes=args.package, jobs=args.jobs)
        tempdirs += results

    if not tempdirs:
        print("No coverage results produced")
        sys.exit(-1)

    # Merge all coverage results together
    cov_path = args.output
    if not cov_path:
        cov_path = os.path.join(base_dir, "rs/target/cov")
    out_paths = list(map(lambda tempdir: tempdir[1], tempdirs))
    kcov_merge(cov_path, out_paths)

    # Delete all the tempdirs
    for tempdir in tempdirs:
        tempdir[0].cleanup()

    print("Coverage results written to %s" % cov_path)
