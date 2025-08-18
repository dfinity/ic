#!/usr/bin/env python3
#
#   targets.py [-h] [--skip_long_tests] [--base BASE] [--head HEAD] {build,test,check}
#
# This script determines which Bazel targets should be built or tested and writes them separated by newlines to stdout.
#
# If --base is passed only include targets with modified inputs in `git diff --name-only --merge-base $BASE $HEAD`.
# When --head is not provided defaults to HEAD.
#
# If --skip_long_tests is passed, tests tagged with 'long_test' will be excluded.
#
# ./PULL_REQUEST_BAZEL_TARGETS is taken into account to explicitly return targets based on modified files
# even though they're not an explicit dependency of a bazel target or are tagged as `long_test`.
#
# When the command is `check` the PULL_REQUEST_BAZEL_TARGETS file is checked for correctness.
#
# The script will print the bazel query to stderr which is useful for debugging:
#   ci/bazel-scripts/targets.py --skip_long_tests --base=master.. test
#   bazel query --keep_going '(((kind(".*_test", //...)) except attr(tags, long_test, //...)) + set(//pre-commit:shfmt-check //pre-commit:ruff-lint)) except attr(tags, manual, //...)'

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path
from typing import Set

# The file specifying which bazel targets to test explicitly on PRs based on which file modifications
# regardless of whether those targets explicitly depend on those files or whether they're tagged as `long_test`.
PULL_REQUEST_BAZEL_TARGETS = "PULL_REQUEST_BAZEL_TARGETS"

# Return all bazel targets (//...) sans the long_tests (if --skip_long_tests is specified)
# in case any file is modified matching any of the following globs:
all_targets_globs = ["*.bazel", "*.bzl", ".bazelrc", ".bazelversion", "mainnet-*-revisions.json", ".github/*"]


def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def die(*args, **kwargs):
    log(*args, **kwargs)
    sys.exit(1)


def load_explicit_targets() -> dict[str, Set[str]]:
    """
    Load and parse explicit targets from the PULL_REQUEST_BAZEL_TARGETS file.
    Returns a dictionary mapping globbing patterns
    to a set of targets to test explicitly on PRs.
    """
    lines = Path(PULL_REQUEST_BAZEL_TARGETS).read_text().splitlines()

    # First filter out comments and blank lines. We use gitignore-style comment handling.
    # See: https://git-scm.com/docs/gitignore#_pattern_format
    # * A blank line matches no files, so it can serve as a separator for readability.
    # * A line starting with # serves as a comment. (discard it entirely).
    # * Put a backslash ("\") in front of the first hash for patterns that begin with a hash.
    content_lines = []
    for line in lines:
        if line.startswith("#") or len(line) == 0 or line.isspace():
            continue
        if line.startswith("\\#"):
            content_lines.append(line[1:])  # drop the escaping backslash
        else:
            content_lines.append(line)

    explicit_targets = []
    for line in content_lines:
        # Indented lines are considered part of the previous list of targets.
        if len(line) > 0 and line[0].isspace():
            if len(explicit_targets) == 0:
                raise ValueError(f"Unexpected indentation in {PULL_REQUEST_BAZEL_TARGETS} for line: '{line}'")
            targets = line.split()
            explicit_targets[-1][1].update(targets)
        else:
            parts = line.split()
            pattern = parts[0]  # Blank lines have been filtered out so we have at least a pattern.
            targets = set(parts[1:])  # Note we accept an empty set of targets.
            explicit_targets.append((pattern, targets))

    # Turn the list of explicit targets into a dictionary to unify equivalent patterns.
    explicit_targets_dict = {}
    for pattern, targets in explicit_targets:
        explicit_targets_dict[pattern] = explicit_targets_dict.get(pattern, set()) | targets

    return explicit_targets_dict


def diff_only_query(command: str, base: str, head: str, skip_long_tests: bool) -> str:
    """
    Return a bazel query for all targets that have modified inputs in the specified git commit range. Taking into account:
    * To return all targets in case files matching all_targets_globs are modified.
    * To only include test targets in case the bazel command was 'test'.
    * To exclude long_tests if requested.
    """
    modified_files = subprocess.run(
        ["git", "diff", "--name-only", "--merge-base", base, head], check=True, capture_output=True, text=True
    ).stdout.splitlines()

    log("Calculating targets to test for the following {n} modified files:".format(n=len(modified_files)))
    for file in modified_files:
        log(file)

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

    # Next, add the explicit targets from the PULL_REQUEST_BAZEL_TARGETS file that match the modified files:
    explicit_targets: Set[str] = set()
    for pattern, explicit_targets_for_pattern in load_explicit_targets().items():
        if len(fnmatch.filter(modified_files, pattern)) > 0:
            explicit_targets |= explicit_targets_for_pattern
    explicit_targets_union = " ".join(explicit_targets)
    query = f"({query}) + set({explicit_targets_union})"

    return query


def targets(command: str, skip_long_tests: bool, base: str | None, head: str | None):
    """Print the bazel targets to build or test to stdout."""
    # If no base is specified, form a query to return all targets
    # but exclude those tagged with 'long_test' (in case --skip_long_tests was specified).
    # Otherwise return a query for all targets that have modified inputs in the specified
    # git commit range taking several factors into account:
    query = (
        ("//..." + (" except attr(tags, long_test, //...)" if skip_long_tests else ""))
        if base is None
        else diff_only_query(command, base, "HEAD" if head is None else head, skip_long_tests)
    )

    # Finally, exclude targets tagged with 'manual' to avoid running manual tests:
    query = f"({query}) except attr(tags, manual, //...)"

    log(f"bazel query --keep_going '{query}'")
    result = subprocess.run(["bazel", "query", "--keep_going", query], stderr=subprocess.PIPE, text=True)

    # As described above, when the query contains files not tracked by bazel,
    # --keep_going will ignore them but will return the special exit code 3 which we ignore:
    if result.returncode not in (0, 3):
        log(f"Error running `bazel query --keep_going '{query}'`:\n" + result.stderr)
        sys.exit(result.returncode)


def check():
    """
    Exit with 0 if PULL_REQUEST_BAZEL_TARGETS:
    * can be read and parsed.
    * each pattern matches at least one file tracked by git.
    * each pattern has at least one explicit target.
    * each target is valid and exists.
    Otherwise print all errors to stderr and exit with 1.
    """
    try:
        explicit_targets = load_explicit_targets()
    except Exception as e:
        die(f"Error loading {PULL_REQUEST_BAZEL_TARGETS}: {e}!")

    all_files = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True).stdout.splitlines()

    errors = []
    for pattern, explicit_targets_for_pattern in explicit_targets.items():
        matches = fnmatch.filter(all_files, pattern)
        n = len(matches)
        if n == 0:
            errors.append(f"Pattern '{pattern}' doesn't match any files tracked by git!")
        else:
            # Log successful matches which is useful for debugging
            # or can be linked to on github.com to inform users of
            # potentially too wide or otherwise incorrect patterns.
            # Note that the final ' ' is necessary for GitHub not
            # to filter the empty line which would hurt readability.
            log(f"Pattern '{pattern}' matches {n} files:\n" + "\n".join(matches) + "\n ")

        if len(explicit_targets_for_pattern) == 0:
            errors.append(f"Pattern '{pattern}' has no explicit targets!")

        for target in explicit_targets_for_pattern:
            result = subprocess.run(["bazel", "query", target], capture_output=True, text=True)
            if result.returncode != 0:
                indentation = "    "
                indented_error_msg = f"{indentation}" + f"\n{indentation}".join(result.stderr.strip().splitlines())
                errors.append(f"Pattern '{pattern}' has problematic target '{target}':\n{indented_error_msg}")

    n = len(errors)
    if n > 0:
        die(f"Encountered the following {n} errors:\n" + "\n".join(errors))

    exit(0)


def main():
    parser = argparse.ArgumentParser(description="Return bazel targets which should be build/tested")
    parser.add_argument(
        "command",
        choices=["build", "test", "check"],
        help="Bazel command to generate targets for. If 'check' then check PULL_REQUEST_BAZEL_TARGETS for correctness",
    )
    parser.add_argument("--skip_long_tests", action="store_true", help="Exclude tests tagged as 'long_test'")
    parser.add_argument(
        "--base",
        help="Only include targets with modified inputs in `git diff --name-only --merge-base $BASE $HEAD`. When --head is not provided defaults to HEAD.",
    )
    parser.add_argument("--head", help="See --base.")
    args = parser.parse_args()

    if args.command == "check":
        check()

    targets(args.command, args.skip_long_tests, args.base, args.head)


if __name__ == "__main__":
    main()
