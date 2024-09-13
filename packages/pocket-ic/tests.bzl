"""
This module defines shared dependency lists for the pocket-ic library and tests and a function to declare pocket-ic tests based on a given pocket-ic server.
"""

load("@rules_rust//rust:defs.bzl", "rust_test_suite")

DEPENDENCIES = [
    # Keep sorted.
    "@crate_index//:base64",
    "@crate_index//:candid",
    "@crate_index//:hex",
    "@crate_index//:ic-cdk",
    "@crate_index//:reqwest",
    "@crate_index//:schemars",
    "@crate_index//:serde",
    "@crate_index//:serde_bytes",
    "@crate_index//:serde_json",
    "@crate_index//:sha2",
    "@crate_index//:slog",
    "@crate_index//:tokio",
    "@crate_index//:tracing",
    "@crate_index//:tracing-appender",
    "@crate_index//:tracing-subscriber",
]

MACRO_DEPENDENCIES = []

TEST_DEPENDENCIES = [
    # Keep sorted.
    "//rs/rosetta-api/icp_ledger",
    "//rs/test_utilities/load_wasm",
    "//rs/types/base_types",
    "//rs/universal_canister/lib",
    "@crate_index//:candid_parser",
    "@crate_index//:ed25519-dalek",
    "@crate_index//:flate2",
    "@crate_index//:k256",
    "@crate_index//:lazy_static",
    "@crate_index//:wat",
]

def pocket_ic_tests(name_suffix, pocket_ic_server):
    """
    Declares a number of rust_test_suites that test the pocket-ic library against the given pocket_ic_server.

    Args:
      name_suffix: to differentiate the declared rust_test_suites from other invocations
        of this macro the names of the tests are suffixed with this string.
      pocket_ic_server: which pocket-ic server to use.
        For example "//rs/pocket_ic_server:pocket-ic-server" or "//:mainnet_pocket_ic".
    """

    suffix = "_pocket_ic_server_" + name_suffix
    rust_test_suite(
        name = "test" + suffix,
        size = "small",
        srcs = ["tests/tests.rs"],
        data = [
            "tests/counter.wasm",
            "tests/icp_ledger.wasm",
            ":test_canister.wasm",
            pocket_ic_server,
        ],
        env = {
            "POCKET_IC_BIN": "$(rootpath " + pocket_ic_server + ")",
            "COUNTER_WASM": "packages/pocket-ic/tests/counter.wasm",
            "LEDGER_WASM": "packages/pocket-ic/tests/icp_ledger.wasm",
            "TEST_WASM": "$(rootpath :test_canister.wasm)",
        },
        flaky = False,
        proc_macro_deps = MACRO_DEPENDENCIES,
        deps = [":pocket-ic"] + DEPENDENCIES + TEST_DEPENDENCIES,
    )

    rust_test_suite(
        name = "restart" + suffix,
        size = "medium",
        srcs = ["tests/restart.rs"],
        data = [
            pocket_ic_server,
        ],
        env = {
            "POCKET_IC_BIN": "$(rootpath " + pocket_ic_server + ")",
        },
        flaky = False,
        proc_macro_deps = MACRO_DEPENDENCIES,
        deps = [":pocket-ic"] + DEPENDENCIES + TEST_DEPENDENCIES,
    )

    rust_test_suite(
        name = "slow" + suffix,
        size = "medium",
        srcs = ["tests/slow.rs"],
        data = [
            pocket_ic_server,
        ],
        env = {
            "POCKET_IC_BIN": "$(rootpath " + pocket_ic_server + ")",
        },
        flaky = False,
        proc_macro_deps = MACRO_DEPENDENCIES,
        tags = ["cpu:8"],
        deps = [":pocket-ic"] + DEPENDENCIES + TEST_DEPENDENCIES,
    )
