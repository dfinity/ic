"""
Common dependencies for system-tests.
"""

load("@mainnet_icos_versions//:defs.bzl", "MAINNET_APP", "MAINNET_NNS")

MAINNET_ENV = {
    "MAINNET_NNS_GUESTOS_REVISION_ENV": MAINNET_NNS["version"],
    "MAINNET_APP_GUESTOS_REVISION_ENV": MAINNET_APP["version"],
}

NNS_CANISTER_WASM_PROVIDERS = {
    "registry-canister_test": {
        "tip-of-branch": "//rs/registry/canister:registry-canister-test",
        "mainnet": "@mainnet_canisters//:registry.wasm.gz",
    },
    "governance-canister_test": {
        "tip-of-branch": "//rs/nns/governance:governance-canister-test",
        "mainnet": "@mainnet_canisters//:governance.wasm.gz",
    },
    "ledger-canister": {
        "tip-of-branch": "//rs/ledger_suite/icp/ledger:ledger-canister-wasm",
        "mainnet": "@mainnet_canisters//:ledger.wasm.gz",
    },
    "root-canister": {
        "tip-of-branch": "//rs/nns/handlers/root/impl:root-canister",
        "mainnet": "@mainnet_canisters//:root.wasm.gz",
    },
    "cycles-minting-canister": {
        "tip-of-branch": "//rs/nns/cmc:cycles-minting-canister",
        "mainnet": "@mainnet_canisters//:cycles-minting.wasm.gz",
    },
    "lifeline_canister": {
        "tip-of-branch": "//rs/nns/handlers/lifeline/impl:lifeline_canister",
        "mainnet": "@mainnet_canisters//:lifeline.wasm.gz",
    },
    "genesis-token-canister": {
        "tip-of-branch": "//rs/nns/gtc:genesis-token-canister",
        "mainnet": "@mainnet_canisters//:genesis-token.wasm.gz",
    },
    "sns-wasm-canister": {
        "tip-of-branch": "//rs/nns/sns-wasm:sns-wasm-canister",
        "mainnet": "@mainnet_canisters//:sns-wasm.wasm.gz",
    },
    "node-rewards": {
        "tip-of-branch": "//rs/node_rewards/canister:node-rewards-canister",
        "mainnet": "@mainnet_canisters//:node-rewards.wasm.gz",
    },
    "migration-canister": {
        "tip-of-branch": "//rs/migration_canister:migration-canister",
        "mainnet": "@mainnet_canisters//:migration.wasm.gz",
    },
}

SNS_CANISTER_WASM_PROVIDERS = {
    "sns-root-canister": {
        "tip-of-branch": "//rs/sns/root:sns-root-canister",
        "mainnet": "@mainnet_canisters//:sns_root.wasm.gz",
    },
    "sns-governance-canister": {
        "tip-of-branch": "//rs/sns/governance:sns-governance-canister",
        "mainnet": "@mainnet_canisters//:sns_governance.wasm.gz",
    },
    "sns-swap-canister": {
        "tip-of-branch": "//rs/sns/swap:sns-swap-canister",
        "mainnet": "@mainnet_canisters//:swap.wasm.gz",
    },
    "ic-icrc1-ledger": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/ledger:ledger_canister",
        "mainnet": "@mainnet_canisters//:sns_ledger.wasm.gz",
    },
    "ic-icrc1-archive": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/archive:archive_canister",
        "mainnet": "@mainnet_canisters//:sns_archive.wasm.gz",
    },
    "ic-icrc1-index-ng": {
        "tip-of-branch": "//rs/ledger_suite/icrc1/index-ng:index_ng_canister",
        "mainnet": "@mainnet_canisters//:sns_index.wasm.gz",
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

    runtime_deps = {
        "{}_WASM_PATH".format(cname.upper().replace("-", "_")): target
        for target, cname in targets.items()
    }
    return runtime_deps

NNS_CANISTER_RUNTIME_DEPS = canister_runtime_deps_impl(
    canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = NNS_CANISTER_WASM_PROVIDERS.keys(),
)

MAINNET_NNS_CANISTER_RUNTIME_DEPS = canister_runtime_deps_impl(
    canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = [],
)

SNS_CANISTER_RUNTIME_DEPS = canister_runtime_deps_impl(
    canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
    qualifying_canisters = SNS_CANISTER_WASM_PROVIDERS.keys(),
)

IC_GATEWAY_RUNTIME_DEPS = {
    "IC_GATEWAY_UVM_CONFIG_IMAGE_PATH": "//rs/tests:ic_gateway_uvm_config_image",
}

COUNTER_CANISTER_RUNTIME_DEPS = {
    "COUNTER_CANISTER_WAT_PATH": "//rs/tests:counter.wat",
}

XNET_TEST_CANISTER_RUNTIME_DEPS = {
    "XNET_TEST_CANISTER_WASM_PATH": "//rs/rust_canisters/xnet_test:xnet-test-canister",
}

UNIVERSAL_CANISTER_RUNTIME_DEPS = {
    "UNIVERSAL_CANISTER_WASM_PATH": "//rs/universal_canister/impl:universal_canister.wasm.gz",
}

MESSAGE_CANISTER_RUNTIME_DEPS = {
    "MESSAGE_CANISTER_WASM_PATH": "//rs/tests/test_canisters/message:message.wasm.gz",
}

SIGNER_CANISTER_RUNTIME_DEPS = {
    "SIGNER_CANISTER_WASM_PATH": "//rs/tests/test_canisters/signer:signer.wasm.gz",
}

IMPERSONATE_UPSTREAMS_RUNTIME_DEPS = {
    "IMPERSONATE_UPSTREAMS_UVM_CONFIG_PATH": "//rs/tests:impersonate_upstreams_uvm_config_image",
}

CANISTER_SANDBOX_RUNTIME_DEPS = {
    "SANDBOX_BINARY": "//rs/canister_sandbox:canister_sandbox",
    "LAUNCHER_BINARY": "//rs/canister_sandbox:sandbox_launcher",
    "COMPILER_BINARY": "//rs/canister_sandbox:compiler_sandbox",
}
