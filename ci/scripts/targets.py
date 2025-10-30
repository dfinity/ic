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
# However, long_tests of which a direct source file has been modified will be included.
#
# Finally ./PULL_REQUEST_BAZEL_TARGETS is taken into account to explicitly return targets based on modified files
# even though they're not an explicit dependency of a bazel target or are tagged as `long_test`.
#
# When the command is `check` the PULL_REQUEST_BAZEL_TARGETS file is checked for correctness.
#
# The script will print the bazel query to stderr which is useful for debugging:
#   ci/scripts/targets.py --skip_long_tests --base=master test
#   bazel query --keep_going '((((kind(".*_test", rdeps(//..., set("ci/scripts/targets.py")))) except attr(tags, long_test, //...)) + attr(tags, long_test, rdeps(//..., set("ci/scripts/targets.py"), 2))) + set(//pre-commit:ruff-lint)) except attr(tags, "manual|system_test_large|system_test_benchmark|fuzz_test|fi_tests_nightly|nns_tests_nightly|pocketic_tests_nightly", //...)'

import argparse
import fnmatch
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Set

# The file specifying which bazel targets to test explicitly on PRs based on which file modifications
# regardless of whether those targets explicitly depend on those files or whether they're tagged as `long_test`.
PULL_REQUEST_BAZEL_TARGETS = "PULL_REQUEST_BAZEL_TARGETS"

# Targets will always be excluded if they have any of the following tags:
EXCLUDED_TAGS = [
    "manual",
    "system_test_large",
    "system_test_benchmark",
    "fuzz_test",
    "fi_tests_nightly",
    "nns_tests_nightly",
    "pocketic_tests_nightly",
]

# Return all bazel targets (//...) sans the long_tests (if --skip_long_tests is specified)
# in case any file is modified matching any of the following globs:
ALL_TARGETS_BLOBS = [
    ".bazelrc",
    ".bazelversion",
    ".github/*",
    "*.bazel",
    "*.bzl",
    "bazel/*",
    "mainnet-*-revisions.json",
]


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
    * To return all targets in case files matching ALL_TARGETS_BLOBS are modified.
    * To only include test targets in case the bazel command was 'test'.
    * To exclude long_tests if requested.
    """
    modified_files = subprocess.run(
        ["git", "diff", "--name-only", "--merge-base", base, head], check=True, capture_output=True, text=True
    ).stdout.splitlines()

    n = len(modified_files)
    log(f"Calculating targets to {command} for the following {n} modified files:")
    for file in modified_files:
        log(file)

    # The files matching the ALL_TARGETS_BLOBS are typically not depended upon by any bazel target
    # but will determine which bazel targets there are in the first place so in case they're modified
    # simply return all bazel targets. Otherwise return all targets that depend on the modified files.
    mfiles = " ".join(f'"{f}"' for f in modified_files)
    query = (
        "//..."
        if any(len(fnmatch.filter(modified_files, glob)) > 0 for glob in ALL_TARGETS_BLOBS)
        # Note that modified_files may contain files not depended upon by any bazel target.
        # `bazel query --keep_going` will ignore those but will return the special exit code 3
        # in case this happens which we check for below. rdeps includes generated file targets
        # which we want to exclude. Including the generated file targets is unnecessary and
        # causes problems with tag exclusion because tags only apply to the rules that generate
        # the files and not the generated files.
        else f"kind(rule, rdeps(//..., set({mfiles})))"
    )

    # The targets returned by this script will be passed to `bazel test` by the caller (in case there are any).
    # So we have to ensure that the targets are either empty or include at least one test
    # otherwise `bazel test` will error with: ERROR: No test targets were found, yet testing was requested
    if command == "test":
        query = f'kind(".*_test|test_suite", {query})'

    # Exclude the long_tests if requested:
    query = f"({query})" + (" except attr(tags, long_test, //...)" if skip_long_tests else "")

    # Include all long_tests of which a "direct" source file has been modified.
    # We specify a depth of 2 since a system-test depends on the test binary (1st degree) which depends
    # on the source file (2nd degree).
    # This will trigger long_tests if some files other than its .rs file are modified but we think
    # this is acceptable since it would be good to run the tests if those files close to the test are modified anyways.
    # To see which source files are within a depth of 2 away from <TEST> use:
    # bazel query 'filter("^//", kind("source file", deps(<TEST>, 2)))'
    query = f"({query}) + attr(tags, long_test, rdeps(//..., set({mfiles}), 2))"

    # Next, add the explicit targets from the PULL_REQUEST_BAZEL_TARGETS file that match the modified files:
    explicit_targets: Set[str] = set()
    for pattern, explicit_targets_for_pattern in load_explicit_targets().items():
        if len(fnmatch.filter(modified_files, pattern)) > 0:
            explicit_targets |= explicit_targets_for_pattern
    explicit_targets_union = " ".join(explicit_targets)
    query = f"({query}) + set({explicit_targets_union})"

    return query


def targets(
    command: str,
    skip_long_tests: bool,
    exclude_tags: list[str],
    base: str | None,
    head: str | None,
):
    """Print the bazel targets to build or test to stdout."""
    # If no base is specified, form a query to return all targets
    # but exclude those tagged with 'long_test' (in case --skip_long_tests was specified)
    # and those with any of the excluded tags.
    # Otherwise return a query for all targets that have modified inputs in the specified
    # git commit range taking several factors into account:
    query = (
        ("//..." + (" except attr(tags, long_test, //...)" if skip_long_tests else ""))
        if base is None
        else diff_only_query(command, base, "HEAD" if head is None else head, skip_long_tests)
    )

    # Finally, exclude targets that have any of the excluded tags:
    excluded_tags_regex = "|".join(EXCLUDED_TAGS + exclude_tags)
    query = f'({query}) except attr(tags, "{excluded_tags_regex}", //...)'

    args = ["bazel", "query", "--keep_going", query]
    log(shlex.join(args))
    result = subprocess.run(args, stderr=subprocess.PIPE, text=True)

    # As described above, when the query contains files not tracked by bazel,
    # --keep_going will ignore them but will return the special exit code 3 which we ignore:
    if result.returncode not in (0, 3):
        log(f"Error running `bazel query --keep_going '{query}'`:\n" + result.stderr)
        sys.exit(result.returncode)


def check():
    """
    Exit successfully with 0 if PULL_REQUEST_BAZEL_TARGETS:
    * can be read and parsed.
    * each pattern matches at least one file tracked by git.
    * each pattern has at least one explicit target.
    * each target is valid and when queried results in at least one target after excluding all excluded targets.
    Otherwise print all errors to stderr and exit erroneously with 1.
    """
    try:
        explicit_targets = load_explicit_targets()
    except Exception as e:
        die(f"Error loading {PULL_REQUEST_BAZEL_TARGETS}: {e}!")

    all_files = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True).stdout.splitlines()

    errors = []
    indentation = "    "
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
            excluded_tags_regex = "|".join(EXCLUDED_TAGS)
            query = f'({target}) except attr(tags, "{excluded_tags_regex}", //...)'
            result = subprocess.run(["bazel", "query", query], capture_output=True, text=True)
            if result.returncode != 0:
                indented_error_msg = f"{indentation}" + f"\n{indentation}".join(result.stderr.strip().splitlines())
                errors.append(f"Pattern '{pattern}' has problematic target '{target}':\n{indented_error_msg}")
            elif len(result.stdout.splitlines()) == 0:
                errors.append(
                    f"Pattern '{pattern}' with target '{target}' results in no targets after excluding all manual targets!"
                    + (
                        f"\n{indentation}It might be you're including the manual non-colocated variant of a system-test."
                        + f"\n{indentation}Try '{target}_colocate' instead."
                    )
                    if target.startswith("//rs/tests")
                    else ""
                )

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
        "--exclude_tags", action="append", default=[], help="Exclude targets tagged with the specified tags"
    )
    parser.add_argument(
        "--base",
        help="Only include targets with modified inputs in `git diff --name-only --merge-base $BASE $HEAD`. When --head is not provided defaults to HEAD.",
    )
    parser.add_argument("--head", help="See --base.")
    args = parser.parse_args()

    if args.command == "check":
        check()

    targets(args.command, args.skip_long_tests, args.exclude_tags, args.base, args.head)


if __name__ == "__main__":
    main()
