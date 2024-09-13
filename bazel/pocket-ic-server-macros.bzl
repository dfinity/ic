"""
This module defines the macro rust_test_suite_pocket_ic which declares two rust_test_suites, one which uses the mainnet pocket-ic server and one that uses the pocket-ic server from HEAD.
"""

load("@rules_rust//rust:defs.bzl", "rust_test_suite")

def rust_test_suite_using_pocket_ic_server(name, **kwargs):
    """
    Declares two rust_test_suites, one which uses the mainnet pocket-ic server and one that uses the pocket-ic server from HEAD.

    Args:
      name: the base name of the rust_test_suites.
        The name will be suffixed with "-pocket-ic-server-mainnet" and "-pocket-ic-server-HEAD"
        for the mainnet and HEAD versions of the pocket-ic server respectively,
      **kwargs: the arguments of the rust_test_suite.
    """
    data = kwargs.pop("data", [])
    env = kwargs.pop("env", {})
    rust_test_suite(
        name = name + "-pocket-ic-server-mainnet",
        data = data + ["//:mainnet-pocket-ic"],
        env = env | {
            "POCKET_IC_BIN": "$(rootpath //:mainnet-pocket-ic)",
        },
        **kwargs
    )
    rust_test_suite(
        name = name + "-pocket-ic-server-HEAD",
        data = data + ["//rs/pocket_ic_server:pocket-ic-server"],
        env = env | {
            "POCKET_IC_BIN": "$(rootpath //rs/pocket_ic_server:pocket-ic-server)",
        },
        **kwargs
    )
