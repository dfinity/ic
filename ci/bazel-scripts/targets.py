#!/usr/bin/env python3
#
#   targets.py [-h] [--skip_long_tests] [--commit_range COMMIT_RANGE] {build,test}
#
# This script determines which Bazel targets should be built or tested and writes them separated by newlines to stdout.
#
# If --commit_range is passed only bazel targets will be included that have modified inputs within the specified git COMMIT_RANGE.
#
# If --skip_long_tests is passed, tests tagged with 'long_test' will be excluded.
#
# ./BAZEL_TARGETS is taken into account to explicitly return targets based on modified files
# even though they're not an explicit dependency of a bazel target or are tagged as `long_test`.
#
# The script will print the bazel query to stderr which is useful for debugging:
#   ci/bazel-scripts/targets.py --skip_long_tests --commit_range=master..HEAD test
#   bazel query --keep_going '(((kind(".*_test", //...)) except attr(tags, long_test, //...)) + set(//pre-commit:shfmt-check //pre-commit:ruff-lint)) except attr(tags, manual, //...)'

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path
from typing import Set

BAZEL_TARGETS = "BAZEL_TARGETS"

# Return all bazel targets (//...) sans the long_tests (if --skip_long_tests is specified)
# in case any file is modified matching any of the following globs:
all_targets_globs = ["*.bazel", "*.bzl", ".bazelrc", ".bazelversion", "mainnet-*-revisions.json", ".github/*"]


def load_explicit_targets() -> dict[str, Set[str]]:
    """
    Load and parse explicit targets from the BAZEL_TARGETS file.
    Returns a dictionary mapping globbing patterns
    to a set of targets to test explicitly on PRs.
    """
    lines = Path(BAZEL_TARGETS).read_text().splitlines()

    # First filter out comments. We use gitignore-style comment handling.
    # See: https://git-scm.com/docs/gitignore#_pattern_format
    # - A line starting with # serves as a comment. (discard it entirely).
    # - Put a backslash ("\") in front of the first hash for patterns that begin with a hash.
    nocomment_lines = []
    for line in lines:
        if line.startswith("#"):
            continue
        if line.startswith("\\#"):
            nocomment_lines.append(line[1:])  # drop the escaping backslash
        else:
            nocomment_lines.append(line)

    # Filter out empty or pure whitespace lines:
    nonempty_lines = [line for line in nocomment_lines if line and not line.isspace()]

    explicit_targets = []
    for line in nonempty_lines:
        # Indented lines are considered part of the previous list of targets.
        if len(line) > 0 and line[0].isspace():
            if len(explicit_targets) == 0:
                raise ValueError(f"Unexpected indentation in {BAZEL_TARGETS} for line: '{line}'")
            targets = line.split()
            explicit_targets[-1][1].update(targets)
        else:
            parts = line.split()

            pattern = parts[0]
            targets = set(parts[1:])

            if len(targets) == 0:
                raise ValueError(
                    f"Expected a line with both a file pattern and a space-separated list of at least a single target in {BAZEL_TARGETS} but got: '{line}'"
                )

            explicit_targets.append((pattern, targets))

    # Turn the list of explicit targets into a dictionary to unify equivalent patterns.
    explicit_targets_dict = {}
    for pattern, targets in explicit_targets:
        explicit_targets_dict[pattern] = explicit_targets_dict.get(pattern, set()) | targets

    return explicit_targets_dict


def diff_only_query(command: str, commit_range: str, skip_long_tests: bool) -> str:
    """
    Return a bazel query for all targets that have modified inputs in the specified git commit range. Taking into account:
    * To return all targets in case files matching all_targets_globs are modified.
    * To only include test targets in case the bazel command was 'test'.
    * To exclude long_tests if requested.
    """
    modified_files = subprocess.run(
        ["git", "diff", "--name-only", commit_range], check=True, capture_output=True, text=True
    ).stdout.splitlines()

    # The files matching the all_targets_globs are typically not depended upon by any bazel target
    # but will determine which bazel targets there are in the first place so in case they're modified
    # simply return all bazel targets. Otherwise return all targets that depend on the modified files.
    query = (
        "//..."
        if any(len(fnmatch.filter(modified_files, glob)) > 0 for glob in all_targets_globs)
        # Note that modified_files may contain files not depended upon by any bazel target.
        # `bazel query --keep_going` will ignore those but will return the special exit code 3
        # in case this happens which we check for below.
        else "rdeps(//..., set({targets}))".format(targets=" ".join(modified_files))
    )

    # The targets returned by this script will be passed to `bazel test` by the caller (in case there are any).
    # So we have to ensure that the targets are either empty or include at least one test
    # otherwise `bazel test` will error with: ERROR: No test targets were found, yet testing was requested
    if command == "test":
        query = f'kind(".*_test", {query})'

    # Exclude the long_tests if requested:
    query = f"({query})" + (" except attr(tags, long_test, //...)" if skip_long_tests else "")

    # Next, add the explicit targets from the BAZEL_TARGETS file that match the modified files:
    explicit_targets: Set[str] = set()
    for pattern, explicit_targets_for_pattern in load_explicit_targets().items():
        if len(fnmatch.filter(modified_files, pattern)) > 0:
            explicit_targets |= explicit_targets_for_pattern
    explicit_targets_union = " ".join(explicit_targets)
    query = f"({query}) + set({explicit_targets_union})"

    return query


def main():
    parser = argparse.ArgumentParser(description="Return bazel targets which should be build/tested")
    parser.add_argument("command", choices=["build", "test"], help="Bazel command to generate targets for")
    parser.add_argument("--skip_long_tests", action="store_true", help="Exclude tests tagged as 'long_test'")
    parser.add_argument(
        "--commit_range",
        help="Only include targets with modified inputs in the given git commit range. For example: 'master..HEAD'",
    )
    args = parser.parse_args()

    # If no commit range is specified, form a query to return all targets
    # but exclude those tagged with 'long_test' (in case --skip_long_tests was specified).
    # Otherwise return a query for all targets that have modified inputs in the specified
    # git commit range taking several factors into account:
    query = (
        ("//..." + (" except attr(tags, long_test, //...)" if args.skip_long_tests else ""))
        if args.commit_range is None
        else diff_only_query(args.command, args.commit_range, args.skip_long_tests)
    )

    # Finally, exclude targets tagged with 'manual' to avoid running manual tests:
    query = f"({query}) except attr(tags, manual, //...)"

    print(f"bazel query --keep_going '{query}'", file=sys.stderr)
    result = subprocess.run(["bazel", "query", "--keep_going", query], stderr=subprocess.PIPE, text=True)

    # As described above, when the query contains files not tracked by bazel,
    # --keep_going will ignore them but will return the special exit code 3 which we ignore:
    if result.returncode not in (0, 3):
        print(f"Error running `bazel query --keep_going '{query}'`:\n" + result.stderr, file=sys.stderr)
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
