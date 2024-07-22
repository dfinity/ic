"""
This module defines functions for checking backward compatibility of candid interfaces.
"""

def _did_git_test_impl(ctx):
    check_did = ctx.executable._check_did
    script = """#!/usr/bin/env bash

set -xeuo pipefail

readonly mr_title=${{CI_MERGE_REQUEST_TITLE:-NONE}}
if [[ $mr_title == *"[override-didc-check]"* ]]; then
    echo "Found [override-didc-check] in merge request title. Skipping didc_check."
    exit 0
fi

# Note that CI_MERGE_REQUEST_TARGET_BRANCH_SHA is only set on Pull Requests.
# On other events we set the merge_base to HEAD which means we compare the
# did interface file against itself.
readonly merge_base=${{CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-HEAD}}

readonly tmpfile=$(mktemp $TEST_TMPDIR/prev.XXXXXX)
readonly errlog=$(mktemp $TEST_TMPDIR/err.XXXXXX)

if ! git show $merge_base:{did_path} > $tmpfile 2> $errlog; then
    if grep -sq -- "exists on disk, but not in \\|does not exist in 'HEAD'" $errlog; then
        echo "{did_path} is a new file, skipping backwards compatibility check"
        exit 0
    else
        cat $errlog
        exit 1
    fi
fi

echo MERGE_BASE=$merge_base
echo DID_PATH={did_path}

{check_did} {did_path} "$tmpfile"
echo "{did_path} passed candid checks"

# In addition to the usual `didc check after.did before.did` it can be helpful to check the reverse as well.
# This is This is useful when it is expected that clients will "jump the gun", i.e. upgrade before servers.
# This is an unusual (but not unheard of) use case.
if [ {enable_also_reverse} = True ]; then
    echo "running also-reverse check"
    {check_did} "$tmpfile" {did_path}
fi
    """.format(check_did = check_did.short_path, did_path = ctx.file.did.path, enable_also_reverse = ctx.attr.enable_also_reverse)

    ctx.actions.write(output = ctx.outputs.executable, content = script)

    files = depset(direct = [check_did, ctx.file.did, ctx.file._git])
    runfiles = ctx.runfiles(files = files.to_list())

    return [
        DefaultInfo(runfiles = runfiles),
        RunEnvironmentInfo(inherited_environment = ["CI_MERGE_REQUEST_TARGET_BRANCH_SHA", "CI_MERGE_REQUEST_TITLE"]),
    ]

CHECK_DID = attr.label(
    default = Label("//rs/tools/check_did"),
    executable = True,
    allow_single_file = True,
    cfg = "exec",
)

_did_git_test = rule(
    implementation = _did_git_test_impl,
    attrs = {
        "did": attr.label(allow_single_file = True),
        "enable_also_reverse": attr.bool(default = False),
        "_check_did": CHECK_DID,
        "_git": attr.label(allow_single_file = True, default = "//:.git"),
    },
    test = True,
)

def did_git_test(name, did, **kwargs):
    """Defines a test checking whether a Candid interface evolves in a backward-compatible way.

    Args:
      name: the test name.
      did: the Candid file, must be a repository file.
      **kwargs: additional keyword arguments to pass to the test rule.
            enable_also_reverse (bool, optional): whether the test should also run candid checks in reverse order
    """
    kwargs.setdefault("tags", ["local", "no-sandbox", "smoke"])
    _did_git_test(name = name, did = did, **kwargs)
