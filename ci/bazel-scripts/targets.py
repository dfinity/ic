#!/usr/bin/env python3
#
#   targets.py [-h] {build,test}
#
# This script is invoked from .github/actions/bazel-test-all/action.yaml and ci/scripts/run-build-ic.sh
# to print to stdout which Bazel targets should be built or tested.
#
# If the environment variable RUN_ON_DIFF_ONLY is set to "true" only bazel targets will be returned
# that have input files which are modified within the git range $MERGE_BASE_SHA..$BRANCH_HEAD_SHA.
#
# If the environment variable SKIP_LONG_TESTS is set to "true", tests tagged with 'long_test' will be excluded.
#
# The script will print the bazel query to stderr which is useful for debugging:
#   $ SKIP_LONG_TESTS="true" RUN_ON_DIFF_ONLY="true" MERGE_BASE_SHA="master" BRANCH_HEAD_SHA="HEAD" ci/bazel-scripts/targets.py test
#   bazel query --keep_going '((kind(".*_test", rdeps(//..., set()))) except attr(tags, long_test, //...)) except attr(tags, manual, //...)'

import argparse
import fnmatch
import os
import subprocess
import sys

# Return all bazel targets (//...) sans the long_tests (if --skip_long_tests is specified)
# in case any file is modified matching any of the following globs:
all_targets_globs = ["*.bazel", "*.bzl", ".bazelrc", ".bazelversion", "mainnet-*-revisions.json", ".github/*"]


def diff_only_query(command: str, commit_range: str, except_long_tests: str) -> str:
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
    if any(len(fnmatch.filter(modified_files, glob)) > 0 for glob in all_targets_globs):
        query = "//..."
    else:
        # Note that modified_files may contain files not depended upon by any bazel target.
        # `bazel query --keep_going` will ignore those but will return the special exit code 3
        # in case this happens which we check for below.
        query = "rdeps(//..., set({targets}))".format(targets=" ".join(modified_files))

    # Only include test targets if the bazel command is 'test'.
    # This ensures `.github/actions/bazel-test-all/action.yaml exits early
    # to not execute `bazel test` in case there are no targets.
    # It would fail with the following error otherwise:
    # ERROR: No test targets were found, yet testing was requested
    # This could happen for PRs that only modify files that are not depended upon by any test.
    if command == "test":
        query = f'kind(".*_test", {query})'

    # Exclude the long_tests if requested:
    query = f"({query}){except_long_tests}"

    return query


def main():
    parser = argparse.ArgumentParser(description="Return bazel targets which should be build/tested")
    parser.add_argument("command", choices=["build", "test"], help="Bazel command to generate targets for")
    args = parser.parse_args()

    SKIP_LONG_TESTS = os.environ.get("SKIP_LONG_TESTS", "false") == "true"
    RUN_ON_DIFF_ONLY = os.environ.get("RUN_ON_DIFF_ONLY", "false") == "true"

    # Can be added to a query to exclude long tests if requested:
    except_long_tests = " except attr(tags, long_test, //...)" if SKIP_LONG_TESTS else ""

    if RUN_ON_DIFF_ONLY:
        MERGE_BASE_SHA = os.environ.get("MERGE_BASE_SHA", "HEAD")
        BRANCH_HEAD_SHA = os.environ.get("BRANCH_HEAD_SHA", "")
        query = diff_only_query(args.command, f"{MERGE_BASE_SHA}..{BRANCH_HEAD_SHA}", except_long_tests)
    else:
        # If no commit range is specified, form a query to return all targets
        # but exclude those tagged with 'long_test' (in case --skip_long_tests was specified):
        query = f"(//...){except_long_tests}"

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
