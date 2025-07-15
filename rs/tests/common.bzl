"""
Common dependencies for system-tests.
"""

load("@mainnet_icos_versions//:defs.bzl", "mainnet_icos_versions")
load(":qualifying_nns_canisters.bzl", "QUALIFYING_NNS_CANISTERS", "QUALIFYING_SNS_CANISTERS")

GUESTOS_DEV_VERSION = "//ic-os/guestos/envs/dev:version.txt"

GUESTOS_RUNTIME_DEPS = [GUESTOS_DEV_VERSION]

MAINNET_NNS_SUBNET_REVISION = mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]
MAINNET_APPLICATION_SUBNET_REVISION = mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]

MAINNET_ENV = {
    "MAINNET_NNS_SUBNET_REVISION_ENV": MAINNET_NNS_SUBNET_REVISION,
    "MAINNET_APPLICATION_SUBNET_REVISION_ENV": MAINNET_APPLICATION_SUBNET_REVISION,
}

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
    "node-rewards": {
        "tip-of-branch": "//rs/node_rewards/canister:node-rewards-canister",
        "mainnet": "@mainnet_node-rewards-canister//file",
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

GRAFANA_RUNTIME_DEPS = UNIVERSAL_VM_RUNTIME_DEPS

IC_GATEWAY_RUNTIME_DEPS = UNIVERSAL_VM_RUNTIME_DEPS + [
    "//rs/tests:ic_gateway_uvm_config_image",
]

COUNTER_CANISTER_RUNTIME_DEPS = ["//rs/tests:counter.wat"]

CANISTER_HTTP_RUNTIME_DEPS = [
    "//rs/tests/networking/canister_http:http_uvm_config_image",
]

XNET_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/xnet_test:xnet-test-canister"]

STATESYNC_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/statesync_test:statesync-test-canister"]

UNIVERSAL_CANISTER_RUNTIME_DEPS = [
    "//rs/universal_canister/impl:universal_canister.wasm.gz",
]

UNIVERSAL_CANISTER_ENV = {
    "UNIVERSAL_CANISTER_WASM_PATH": "$(rootpath //rs/universal_canister/impl:universal_canister.wasm.gz)",
}

MESSAGE_CANISTER_RUNTIME_DEPS = [
    "//rs/tests/test_canisters/message:message.wasm.gz",
]

MESSAGE_CANISTER_ENV = {
    "MESSAGE_CANISTER_WASM_PATH": "$(rootpath //rs/tests/test_canisters/message:message.wasm.gz)",
}

SIGNER_CANISTER_RUNTIME_DEPS = [
    "//rs/tests/test_canisters/signer:signer.wasm.gz",
]

SIGNER_CANISTER_ENV = {
    "SIGNER_CANISTER_WASM_PATH": "$(rootpath //rs/tests/test_canisters/signer:signer.wasm.gz)",
}
