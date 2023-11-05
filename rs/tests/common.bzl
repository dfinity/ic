"""
Common dependencies for system-tests.
"""

load("@crate_index//:defs.bzl", "all_crate_deps")
load(":qualifying_nns_canisters.bzl", "QUALIFYING_NNS_CANISTERS", "QUALIFYING_SNS_CANISTERS")

DEPENDENCIES = all_crate_deps(package_name = "rs/tests") + [
    "//packages/icrc-ledger-agent:icrc_ledger_agent",
    "//packages/icrc-ledger-types:icrc_ledger_types",
    "//rs/artifact_pool",
    "//rs/backup",
    "//rs/bitcoin/ckbtc/agent",
    "//rs/bitcoin/ckbtc/kyt",
    "//rs/bitcoin/ckbtc/minter",
    "//rs/boundary_node/certificate_issuance/certificate_orchestrator_interface",
    "//rs/canister_client",
    "//rs/canister_client/sender",
    "//rs/certification",
    "//rs/config",
    "//rs/constants",
    "//rs/crypto",
    "//rs/crypto/sha2",
    "//rs/crypto/test_utils/reproducible_rng",
    "//rs/crypto/tree_hash",
    "//rs/cup_explorer",
    "//rs/cycles_account_manager",
    "//rs/http_utils",
    "//rs/interfaces",
    "//rs/interfaces/registry",
    "//rs/nervous_system/common",
    "//rs/nervous_system/common/test_keys",
    "//rs/nervous_system/proto",
    "//rs/nervous_system/root",
    "//rs/nns/cmc",
    "//rs/nns/common",
    "//rs/nns/constants",
    "//rs/nns/governance",
    "//rs/nns/gtc",
    "//rs/nns/handlers/lifeline/impl:lifeline",
    "//rs/nns/handlers/root/impl:root",
    "//rs/nns/init",
    "//rs/nns/sns-wasm",
    "//rs/nns/test_utils",
    "//rs/phantom_newtype",
    "//rs/prep",
    "//rs/protobuf",
    "//rs/recovery",
    "//rs/recovery/subnet_splitting:subnet_splitting",
    "//rs/registry/canister",
    "//rs/registry/client",
    "//rs/registry/helpers",
    "//rs/registry/keys",
    "//rs/registry/local_registry",
    "//rs/registry/local_store",
    "//rs/registry/local_store/artifacts",
    "//rs/registry/nns_data_provider",
    "//rs/registry/provisional_whitelist",
    "//rs/registry/routing_table",
    "//rs/registry/regedit",
    "//rs/registry/subnet_features",
    "//rs/registry/subnet_type",
    "//rs/registry/transport",
    "//rs/replay",
    "//rs/rosetta-api",
    "//rs/rosetta-api/icrc1",
    "//rs/rosetta-api/icrc1/ledger",
    "//rs/rosetta-api/icp_ledger",
    "//rs/rosetta-api/ledger_canister_blocks_synchronizer/test_utils",
    "//rs/rosetta-api/ledger_core",
    "//rs/rosetta-api/test_utils",
    "//rs/rust_canisters/canister_test",
    "//rs/rust_canisters/dfn_candid",
    "//rs/rust_canisters/dfn_json",
    "//rs/rust_canisters/dfn_core",
    "//rs/rust_canisters/dfn_protobuf",
    "//rs/rust_canisters/http_types",
    "//rs/rust_canisters/on_wire",
    "//rs/rust_canisters/proxy_canister:lib",
    "//rs/rust_canisters/xnet_test",
    "//rs/sns/init",
    "//rs/sns/swap",
    "//rs/sns/root",
    "//rs/sns/governance",
    "//rs/tests/test_canisters/message:lib",
    "//rs/test_utilities",
    "//rs/test_utilities/identity",
    "//rs/tree_deserializer",
    "//rs/types/base_types",
    "//rs/types/ic00_types",
    "//rs/types/types",
    "//rs/types/types_test_utils",
    "//rs/universal_canister/lib",
    "//rs/utils",
    "//rs/boundary_node/discower_bowndary:discower-bowndary",
]

MACRO_DEPENDENCIES = [
    "@crate_index//:async-recursion",
    "@crate_index//:async-trait",
    "@crate_index//:indoc",
]

GUESTOS_DEV_VERSION = "//ic-os/guestos/envs/dev:version.txt"

GUESTOS_RUNTIME_DEPS = [
    GUESTOS_DEV_VERSION,
    "//ic-os:scripts/build-bootstrap-config-image.sh",
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
        "tip-of-branch": "//rs/rosetta-api/icp_ledger/ledger:ledger-canister-wasm-notify-method",
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
        "tip-of-branch": "//rs/rosetta-api/icrc1/ledger:ledger_canister",
        "mainnet": "@mainnet_ic-icrc1-ledger//file",
    },
    "ic-icrc1-archive": {
        "tip-of-branch": "//rs/rosetta-api/icrc1/archive:archive_canister",
        "mainnet": "@mainnet_ic-icrc1-archive//file",
    },
    "ic-icrc1-index": {
        "tip-of-branch": "//rs/rosetta-api/icrc1/index:index_canister",
        "mainnet": "@mainnet_ic-icrc1-index//file",
    },
}

def canister_runtime_deps_impl(name, canister_wasm_providers, qualifying_canisters):
    """Declares a runtime dependency for a canister suite.

    Args:
      name: base name to use for the rule providing the canister WASM.
      canister_wasm_providers: dict with (canister names as keys) and (values representing WASM-producing rules, tip-of-branch or mainnet).
      qualifying_canisters: list of canisters to be qualified for the release, i.e., these should be built from the current branch.
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

    # Include the information about which WASMs were actually picked
    selected = "selected-" + name
    selected_out = selected + ".json"
    selected_map = {("\"" + cname + "\""): ("\"mainnet\"" if provider.startswith("@mainnet_") else "\"tip-of-branch\"") for provider, cname in targets.items()}
    native.genrule(
        name = selected,
        outs = [selected_out],
        cmd = """echo "{selected_map}" > $(OUTS)""".format(selected_map = selected_map),
    )
    targets[selected] = selected_out

    symlink_dir(
        name = name,
        targets = targets,
    )

def mainnet_nns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = [],
    )

def tip_nns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = NNS_CANISTER_WASM_PROVIDERS.keys(),
    )

def qualifying_nns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = NNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = QUALIFYING_NNS_CANISTERS,
    )

def mainnet_sns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = [],
    )

def tip_sns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = SNS_CANISTER_WASM_PROVIDERS.keys(),
    )

def qualifying_sns_canisters(name):
    canister_runtime_deps_impl(
        name = name,
        canister_wasm_providers = SNS_CANISTER_WASM_PROVIDERS,
        qualifying_canisters = QUALIFYING_SNS_CANISTERS,
    )

NNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:tip-nns-canisters"]

MAINNET_NNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:mainnet-nns-canisters"]

QUALIFYING_NNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:qualifying-nns-canisters"]

SNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:tip-sns-canisters"]

MAINNET_SNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:mainnet-sns-canisters"]

QUALIFYING_SNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:qualifying-sns-canisters"]

UNIVERSAL_VM_RUNTIME_DEPS = [
    "//rs/tests:create-universal-vm-config-image.sh",
]

GRAFANA_RUNTIME_DEPS = UNIVERSAL_VM_RUNTIME_DEPS + [
    "//rs/tests:grafana_dashboards",
]

API_BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS = [
    "//ic-os/boundary-api-guestos/envs/dev:disk-img.tar.zst.sha256",
    "//ic-os/boundary-api-guestos/envs/dev:disk-img.tar.zst.cas-url",
    "//ic-os/boundary-api-guestos:scripts/build-bootstrap-config-image.sh",
]

BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS = [
    "//ic-os/boundary-guestos/envs/dev:disk-img.tar.zst.cas-url",
    "//ic-os/boundary-guestos/envs/dev:disk-img.tar.zst.sha256",
    "//ic-os/boundary-guestos:scripts/build-bootstrap-config-image.sh",
]

BOUNDARY_NODE_GUESTOS_SEV_RUNTIME_DEPS = [
    "//ic-os/boundary-guestos/envs/dev-sev:disk-img.tar.zst.cas-url",
    "//ic-os/boundary-guestos/envs/dev-sev:disk-img.tar.zst.sha256",
]

COUNTER_CANISTER_RUNTIME_DEPS = ["//rs/tests:src/counter.wat"]

CANISTER_HTTP_RUNTIME_DEPS = [
    "//rs/tests:http_uvm_config_image",
]

CUSTOM_DOMAINS_RUNTIME_DEPS = [
    "//rs/tests:custom_domains_uvm_config_image",
    "@asset_canister//file",
]

XNET_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/xnet_test:xnet-test-canister"]

STATESYNC_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/statesync_test:statesync_test_canister"]

def _symlink_dir(ctx):
    dirname = ctx.attr.name
    lns = []
    for target, canister_name in ctx.attr.targets.items():
        ln = ctx.actions.declare_file(dirname + "/" + canister_name)
        file = target[DefaultInfo].files.to_list()[0]
        ctx.actions.symlink(
            output = ln,
            target_file = file,
        )
        lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns))]

symlink_dir = rule(
    implementation = _symlink_dir,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)

def _symlink_dirs(ctx):
    dirname = ctx.attr.name
    lns = []
    for target, childdirname in ctx.attr.targets.items():
        for file in target[DefaultInfo].files.to_list():
            ln = ctx.actions.declare_file(dirname + "/" + childdirname + "/" + file.basename)
            ctx.actions.symlink(
                output = ln,
                target_file = file,
            )
            lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns))]

symlink_dirs = rule(
    implementation = _symlink_dirs,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)
