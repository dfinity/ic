"""
This module defines macros for running tests using the pocket-ic server from both mainnet and HEAD.
"""

def test_using_pocket_ic_server(macro, name, extra_mainnet_tags = [], extra_HEAD_tags = ["manual"], **kwargs):
    """
    Declares two targets as defined by the given test macro, one which uses the mainnet pocket-ic server and one that uses the pocket-ic server from HEAD.

    Args:
      macro: the bazel macro to run. For example: rust_test_suite or rust_test_suite_with_extra_srcs.
      name: the base name of the target.
        The name will be suffixed with "-pocket-ic-server-mainnet" and "-pocket-ic-server-HEAD"
        for the mainnet and HEAD variants of the pocket-ic server respectively,
      extra_mainnet_tags: extra tags assigned to the mainnet pocket-ic server variant.
      extra_HEAD_tags: extra tags assigned to the HEAD pocket-ic server variant.
        Defaults to "manual" to not automatically run this variant.
      **kwargs: the arguments of the bazel macro.
    """
    data = kwargs.pop("data", [])
    env = kwargs.pop("env", {})
    tags = kwargs.pop("tags", [])
    macro(
        name = name + "-pocket-ic-server-mainnet",
        data = data + ["//:mainnet-pocket-ic"],
        env = env | {
            "POCKET_IC_BIN": "$(rootpath //:mainnet-pocket-ic)",
        },
        tags = [tag for tag in tags if tag not in extra_mainnet_tags] + extra_mainnet_tags,
        **kwargs
    )
    macro(
        name = name + "-pocket-ic-server-HEAD",
        data = data + ["//rs/pocket_ic_server:pocket-ic-server"],
        env = env | {
            "POCKET_IC_BIN": "$(rootpath //rs/pocket_ic_server:pocket-ic-server)",
        },
        tags = [tag for tag in tags if tag not in extra_HEAD_tags] + extra_HEAD_tags,
        **kwargs
    )
