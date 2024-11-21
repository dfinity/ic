"""
Common dependencies for system-tests.
"""

load(":qualifying_nns_canisters.bzl", "QUALIFYING_NNS_CANISTERS", "QUALIFYING_SNS_CANISTERS")

DEPENDENCIES = [
    "//packages/icrc-ledger-agent:icrc_ledger_agent",
    "//packages/icrc-ledger-types:icrc_ledger_types",
    "//rs/async_utils",
    "//rs/bitcoin/ckbtc/agent",
    "//rs/bitcoin/ckbtc/kyt",
    "//rs/bitcoin/ckbtc/minter",
    "//rs/boundary_node/certificate_issuance/certificate_orchestrator_interface",
    "//rs/boundary_node/discower_bowndary:discower-bowndary",
    "//rs/canister_client",
    "//rs/canister_client/sender",
    "//rs/ledger_suite/icrc1/test_utils",
    "//rs/certification",
    "//rs/config",
    "//rs/limits",
    "//rs/crypto/sha2",
    "//rs/crypto/tree_hash",
    "//rs/crypto/utils/threshold_sig_der",
    "//rs/cup_explorer",
    "//rs/cycles_account_manager",
    "//rs/ethereum/ledger-suite-orchestrator:ledger_suite_orchestrator",
    "//rs/http_utils",
    "//rs/ic_os/deterministic_ips",
    "//rs/interfaces",
    "//rs/interfaces/registry",
    "//rs/nervous_system/clients",
    "//rs/nervous_system/common",
    "//rs/nervous_system/common/test_keys",
    "//rs/nervous_system/proto",
    "//rs/nervous_system/root",
    "//rs/nns/cmc",
    "//rs/nns/common",
    "//rs/nns/constants",
    "//rs/nns/governance/api",
    "//rs/nns/gtc",
    "//rs/nns/handlers/lifeline/impl:lifeline",
    "//rs/nns/handlers/root/impl:root",
    "//rs/nns/init",
    "//rs/nns/sns-wasm",
    "//rs/nns/test_utils",
    "//rs/phantom_newtype",
    "//rs/prep",
    "//rs/protobuf",
    "//rs/registry/canister",
    "//rs/registry/client",
    "//rs/registry/helpers",
    "//rs/registry/keys",
    "//rs/registry/local_registry",
    "//rs/registry/local_store",
    "//rs/registry/local_store/artifacts",
    "//rs/registry/nns_data_provider",
    "//rs/registry/provisional_whitelist",
    "//rs/registry/regedit",
    "//rs/registry/routing_table",
    "//rs/registry/subnet_features",
    "//rs/registry/subnet_type",
    "//rs/registry/transport",
    "//rs/replay",
    "//rs/rosetta-api/icp:rosetta-api",
    "//rs/ledger_suite/icp:icp_ledger",
    "//rs/ledger_suite/icrc1",
    "//rs/ledger_suite/icrc1/index-ng",
    "//rs/ledger_suite/icrc1/ledger",
    "//rs/rosetta-api/icp/ledger_canister_blocks_synchronizer/test_utils",
    "//rs/ledger_suite/common/ledger_core",
    "//rs/rosetta-api/common/rosetta_core:rosetta-core",
    "//rs/rosetta-api/icp/test_utils",
    "//rs/rust_canisters/canister_test",
    "//rs/rust_canisters/dfn_candid",
    "//rs/rust_canisters/dfn_json",
    "//rs/rust_canisters/dfn_protobuf",
    "//rs/rust_canisters/http_types",
    "//rs/rust_canisters/on_wire",
    "//rs/rust_canisters/xnet_test",
    "//rs/sns/governance",
    "//rs/sns/init",
    "//rs/sns/root",
    "//rs/sns/swap",
    "//rs/sys",
    "//rs/test_utilities",
    "//rs/test_utilities/identity",
    "//rs/test_utilities/time",
    "//rs/test_utilities/types",
    "//rs/tests/consensus/utils",
    "//rs/tests/consensus/tecdsa/utils",
    "//rs/tests/driver:ic-system-test-driver",
    "//rs/tests/test_canisters/message:lib",
    "//rs/tree_deserializer",
    "//rs/types/base_types",
    "//rs/types/management_canister_types",
    "//rs/registry/canister/api",
    "//rs/types/types_test_utils",
    "//rs/types/types",
    "//rs/types/wasm_types",
    "//rs/universal_canister/lib",
    "@crate_index//:anyhow",
    "@crate_index//:axum",
    "@crate_index//:assert_matches",
    "@crate_index//:assert-json-diff",
    "@crate_index//:backon",
    "@crate_index//:base64",
    "@crate_index//:bincode",
    "@crate_index//:bitcoincore-rpc",
    "@crate_index//:candid",
    "@crate_index//:chacha20poly1305",
    "@crate_index//:chrono",
    "@crate_index//:clap",
    "@crate_index//:crossbeam-channel",
    "@crate_index//:ed25519-dalek",
    "@crate_index//:flate2",
    "@crate_index//:futures",
    "@crate_index//:hex",
    "@crate_index//:humantime",
    "@crate_index//:ic-agent",
    "@crate_index//:ic-btc-interface",
    "@crate_index//:ic-cdk",
    "@crate_index//:ic-utils",
    "@crate_index//:itertools",
    "@crate_index//:json5",
    "@crate_index//:k256",
    "@crate_index//:k8s-openapi",
    "@crate_index//:kube",
    "@crate_index//:lazy_static",
    "@crate_index//:leb128",
    "@crate_index//:maplit",
    "@crate_index//:nix",
    "@crate_index//:num_cpus",
    "@crate_index//:num-traits",
    "@crate_index//:once_cell",
    "@crate_index//:openssh-keys",
    "@crate_index//:pem",
    "@crate_index//:proptest",
    "@crate_index//:prost",
    "@crate_index//:quickcheck",
    "@crate_index//:rand_chacha",
    "@crate_index//:rand",
    "@crate_index//:rayon",
    "@crate_index//:rcgen",
    "@crate_index//:regex",
    "@crate_index//:reqwest",
    "@crate_index//:rsa",
    "@crate_index//:rust_decimal",
    "@crate_index//:serde_bytes",
    "@crate_index//:serde_cbor",
    "@crate_index//:serde_json",
    "@crate_index//:serde_yaml",
    "@crate_index//:serde",
    "@crate_index//:sha2",
    "@crate_index//:slog-async",
    "@crate_index//:slog-term",
    "@crate_index//:slog",
    "@crate_index//:ssh2",
    "@crate_index//:strum",
    "@crate_index//:tempfile",
    "@crate_index//:thiserror",
    "@crate_index//:time",
    "@crate_index//:tokio-util",
    "@crate_index//:tokio",
    "@crate_index//:tracing-subscriber",
    "@crate_index//:tracing",
    "@crate_index//:url",
    "@crate_index//:walkdir",
    "@crate_index//:wat",
]

MACRO_DEPENDENCIES = [
    "@crate_index//:async-recursion",
    "@crate_index//:async-trait",
    "@crate_index//:indoc",
    "@crate_index//:strum_macros",
]

GUESTOS_DEV_VERSION = "//ic-os/guestos/envs/dev:version.txt"

GUESTOS_RUNTIME_DEPS = [
    GUESTOS_DEV_VERSION,
    "//ic-os/components:hostos-scripts/build-bootstrap-config-image.sh",
]

MAINNET_REVISION_RUNTIME_DEPS = ["//testnet:mainnet_nns_revision"]

NNS_CANISTER_WASM_PROVIDERS = {
    "registry-canister": {
        "tip-of-branch": "//rs/registry/canister:registry-canister",
        "mainnet": "@mainnet_nns_registry_canister//file",
    },
    "governance-canister_test": {
        "tip-of-branch": "//rs/nns/governance:governance-canister-test",
        "mainnet": "@mainnet_nns_governance_canister//file",
    },
    "ledger-canister_notify-method": {
        "tip-of-branch": "//rs/ledger_suite/icp/ledger:ledger-canister-wasm-notify-method",
        "mainnet": "@mainnet_icp_ledger_canister//file",
    },
    "root-canister": {
        "tip-of-branch": "//rs/nns/handlers/root/impl:root-canister",
        "mainnet": "@mainnet_nns_root-canister//file",
    },
    "cycles-minting-canister": {
        "tip-of-branch": "//rs/nns/cmc:cycles-minting-canister",
        "mainnet": "@mainnet_nns_cycles-minting-canister//file",
    },
    "lifeline_canister": {
        "tip-of-branch": "//rs/nns/handlers/lifeline/impl:lifeline_canister",
        "mainnet": "@mainnet_nns_lifeline_canister//file",
    },
    "genesis-token-canister": {
        "tip-of-branch": "//rs/nns/gtc:genesis-token-canister",
        "mainnet": "@mainnet_nns_genesis-token-canister//file",
    },
    "sns-wasm-canister": {
        "tip-of-branch": "//rs/nns/sns-wasm:sns-wasm-canister",
        "mainnet": "@mainnet_nns_sns-wasm-canister//file",
    },
}

SNS_CANISTER_WASM_PROVIDERS = {
    "sns-root-canister": {
        "tip-of-branch": "//rs/sns/root:sns-root-canister",
        "mainnet": "@mainnet_sns-root-canister//file",
    },
    "sns-governance-canister": {
        "tip-of-branch": "//rs/sns/governance:sns-governance-canister",
        "mainnet": "@mainnet_sns-governance-canister//file",
    },
    "sns-swap-canister": {
        "tip-of-branch": "//rs/sns/swap:sns-swap-canister",
        "mainnet": "@mainnet_sns-swap-canister//file",
    },
    "ic-icrc1-ledger": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/ledger:ledger_canister",
        "mainnet": "@mainnet_ic-icrc1-ledger//file",
    },
    "ic-icrc1-archive": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/archive:archive_canister",
        "mainnet": "@mainnet_ic-icrc1-archive//file",
    },
    "ic-icrc1-index-ng": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/index-ng:index_ng_canister",
        "mainnet": "@mainnet_ic-icrc1-index-ng//file",
    },
}

def canister_runtime_deps_impl(canister_wasm_providers, qualifying_canisters):
    """
    Return the canister runtime dependencies.

    Args:
      canister_wasm_providers: dict with (canister names as keys) and (values representing WASM-producing rules, tip-of-branch or mainnet).
      qualifying_canisters: list of canisters to be qualified for the release, i.e., these should be built from the current branch.

    Returns:
      the runtime dependencies for a canister suite paired with a set of environment variables pointing to the WASMs.
    """
    for cname in qualifying_canisters:
        if cname not in canister_wasm_providers.keys():
            fail("qualifying canisters must be a subset of {}" % canister_wasm_providers.keys())

    targets = {
        (
            providers["tip-of-branch"] if cname in qualifying_canisters else providers["mainnet"]
        ): cname
        for cname, providers in canister_wasm_providers.items()
    }

    runtime_deps = targets.keys()
    env = {
        "{}_WASM_PATH".format(cname.upper().replace("-", "_")): "$(rootpath {})".format(target)
        for target, cname in targets.items()
    }
    return runtime_deps, env

NNS_CANISTER_RUNTIME_DEPS, NNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = NNS_CANISTER_WASM_PROVIDERS.keys(),
)

MAINNET_NNS_CANISTER_RUNTIME_DEPS, MAINNET_NNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = [],
)

QUALIFYING_NNS_CANISTER_RUNTIME_DEPS, QUALIFYING_NNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = QUALIFYING_NNS_CANISTERS,
)

SNS_CANISTER_RUNTIME_DEPS, SNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = SNS_CANISTER_WASM_PROVIDERS.keys(),
)

MAINNET_SNS_CANISTER_RUNTIME_DEPS, MAINNET_SNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = [],
)

QUALIFYING_SNS_CANISTER_RUNTIME_DEPS, QUALIFYING_SNS_CANISTER_ENV = canister_runtime_deps_impl(
    canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = QUALIFYING_SNS_CANISTERS,
)

UNIVERSAL_VM_RUNTIME_DEPS = [
    "//rs/tests:create-universal-vm-config-image.sh",
]

GRAFANA_RUNTIME_DEPS = UNIVERSAL_VM_RUNTIME_DEPS + [
    "//rs/tests:grafana_dashboards",
]

BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS = [
    "//ic-os/boundary-guestos/envs/dev:disk-img.tar.zst.cas-url",
    "//ic-os/boundary-guestos/envs/dev:disk-img.tar.zst.sha256",
    "//ic-os/boundary-guestos:scripts/build-bootstrap-config-image.sh",
]

COUNTER_CANISTER_RUNTIME_DEPS = ["//rs/tests:counter.wat"]

CANISTER_HTTP_RUNTIME_DEPS = [
    "//rs/tests/networking/canister_http:http_uvm_config_image",
]

XNET_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/xnet_test:xnet-test-canister"]

STATESYNC_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/statesync_test:statesync_test_canister"]

IC_MAINNET_NNS_RECOVERY_RUNTIME_DEPS = GUESTOS_RUNTIME_DEPS + \
                                       NNS_CANISTER_RUNTIME_DEPS + \
                                       BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS + \
                                       MAINNET_REVISION_RUNTIME_DEPS + \
                                       GRAFANA_RUNTIME_DEPS + [
    "//rs/sns/cli:sns",
    "//rs/tests:recovery/binaries",
    "//rs/tests/nns:secret_key.pem",
    "@dfx",
    "@idl2json",
    "@sns_quill//:sns-quill",
    "@candid//:didc",
    "//rs/rosetta-api/tvl/xrc_mock:xrc_mock_canister",
]

UNIVERSAL_CANISTER_RUNTIME_DEPS = [
    "//rs/universal_canister/impl:universal_canister.wasm.gz",
]

UNIVERSAL_CANISTER_ENV = {
    "UNIVERSAL_CANISTER_WASM_PATH": "$(rootpath //rs/universal_canister/impl:universal_canister.wasm.gz)",
}
