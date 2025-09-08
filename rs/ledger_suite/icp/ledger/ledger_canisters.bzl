"""
This Bazel file defines the configuration for building the Ledger Canister in Rust.

The `rust_ledger_canister` function is a wrapper around the `rust_canister` rule that
sets up the necessary dependencies, environment variables, and service files required
to build the Ledger Canister.

Usage:
- The `rust_ledger_canister` function is used to instantiate a Rust canister with the
  provided `name` and optional `crate_features`. It simplifies the configuration for
  building the Ledger Canister by predefining common settings such as source files,
  dependencies, and environment variables.
"""

load("//bazel:canisters.bzl", "rust_canister")

LEDGER_CANISTER_DATA = [
    "//rs/ledger_suite/icp:ledger.did",
    "//rs/ledger_suite/icp/ledger:ledger_candid_backwards_compatible.did",
]

LEDGER_CANISTER_RUSTC_ENV = {
    "LEDGER_DID_PATH": "$(execpath //rs/ledger_suite/icp:ledger.did)",
}

LEDGER_CANISTER_DEPS = [
    # Keep sorted.
    "//packages/ic-http-types",
    "//packages/ic-ledger-hash-of:ic_ledger_hash_of",
    "//packages/icrc-ledger-types:icrc_ledger_types",
    "//rs/ledger_suite/common/ledger_canister_core",
    "//rs/ledger_suite/common/ledger_core",
    "//rs/ledger_suite/icp:icp_ledger",
    "//rs/ledger_suite/icrc1",
    "//rs/rust_canisters/canister_log",
    "//rs/rust_canisters/dfn_protobuf",
    "//rs/rust_canisters/on_wire",
    "//rs/types/base_types",
    "@crate_index//:candid",
    "@crate_index//:ciborium",
    "@crate_index//:ic-cdk",
    "@crate_index//:ic-metrics-encoder",
    "@crate_index//:ic-stable-structures",
    "@crate_index//:num-traits",
    "@crate_index//:serde_bytes",
]

def rust_ledger_canister(name, extra_deps = [":ledger"], crate_features = None):
    rust_canister(
        name = name,
        srcs = ["src/main.rs"],
        compile_data = LEDGER_CANISTER_DATA,
        data = LEDGER_CANISTER_DATA,
        rustc_env = LEDGER_CANISTER_RUSTC_ENV,
        service_file = "//rs/ledger_suite/icp:ledger.did",
        deps = LEDGER_CANISTER_DEPS + extra_deps,
        crate_features = crate_features if crate_features else [],
        proc_macro_deps = [
            # Keep sorted.
        ],
    )
