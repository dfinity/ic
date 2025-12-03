"""
This module defines functions for checking backward compatibility of candid interfaces.
"""

load("@rules_shell//shell:sh_test.bzl", "sh_test")

def did_git_test(name, did, enable_also_reverse = False, **kwargs):
    """Defines a test checking whether a Candid interface evolves in a backward-compatible way.

    Args:
      name: the test name.
      did: the Candid file, must be a repository file.
      enable_also_reverse (bool, optional): whether the test should also run candid checks in reverse order
      **kwargs: additional keyword arguments to pass to the test rule.
    """

    tags = kwargs.pop("tags", [])
    for tag in ["smoke", "didc"]:
        if not tag in tags:
            tags.append(tag)

    sh_test(
        name = name,
        srcs = ["@//bazel/candid:candid-check.sh"],
        data = ["//rs/tools/check_did", did, "//:WORKSPACE.bazel"],
        env = {
            "DID_CHECK_BIN": "$(rootpath //rs/tools/check_did)",
            "ENABLE_ALSO_REVERSE": "1" if enable_also_reverse else "",
            "DID_PATH": "$(rootpath " + did + ")",
            "WORKSPACE_FILE": "$(rootpath //:WORKSPACE.bazel)",
        },
        env_inherit = ["DID_CHECK_REV"],
        tags = tags,
        **kwargs
    )
