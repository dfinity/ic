"""
This module defines a macro for running tests using the pocket-ic server from both mainnet and HEAD.
"""

def test_using_pocket_ic_server(macro, name, extra_mainnet_tags = [], extra_HEAD_tags = ["manual"], **kwargs):
    """
    Declares two targets as defined by the given test macro, one which uses the mainnet pocket-ic server and one that uses the pocket-ic server from HEAD.

    The idea behind this macro is that NNS and other canisters need to be tested
    against the mainnet version of the replica since that version would be active
    when the canisters would be released at that point in time. Therefor tests that
    check these canisters need to run with the mainnet version of the pocket-ic server
    to replicate production as much as possible.

    Additionally not letting canister tests depend on the HEAD version of the pocket-ic server means
    less time spend on CI whenever IC components (which the pocket-ic server depends on) are modified.

    However it's still useful to also test the canisters against the HEAD version of the IC.
    Therefore an additional target is declared that runs the test using the HEAD version of the
    pocket-ic server but this target is tagged as "manual" by default to not run it automatically on CI.
    Most test override this "manual" tag with some tag to run it on a schedule like
    "nns_tests_nightly" or "fi_tests_nightly".

    In a way this macro is the mirror image of the rs/tests/system_tests.bzl:system_test_nns() macro.

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
