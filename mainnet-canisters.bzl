"""
This module defines Bazel targets for the mainnet versions of the core NNS, SNS, and ck canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "ee407c6f48c892f8f6bd2cc6558d7d897d89b1990c931125ba48bd9513e7c425"),
    "ledger": ("bb76748d1d225c08d88037e99ca9a066f97de496", "96f00dc30c8040992c454e285eca25ac6f14e06210417742caf7d10554a9d57f"),
    "archive": ("8d80b3b3703988645a604641f8d600d525bb5c21", "d7229caa5106454413c5382437cfb0864dedc36058611111debf94da0258998b"),
    "index": ("463296c0bc82ad5999b70245e5f125c14ba7d090", "8157f5cba913d9db25a2c54ebf823d4edcc50cce00b97a18e5d33c2f73e59c93"),
    "root": ("b9a20425f94eb1433385a7ed0c59c41095c17b7b", "0c791dc6010b041112ab23935d1be8ca28e2b7ae1374c0051a1dde12262b658b"),
    "registry": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "21788e6c715ce1dd6189151f32b6b3216ed7df9e97935ab11bd3c227c335225c"),
    "lifeline": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "614d7d418c4eaa9984b6c3f4afe2d1e45b2f110369edcc2dc767792181742348"),
    "genesis-token": ("87f48a595b6f666fbc7fe6ad4081aa98fd113d12", "dd71862512af57e938e01810be016e17431912d9ca0ea3952bc04015eb02acc4"),
    "cycles-minting": ("b9a20425f94eb1433385a7ed0c59c41095c17b7b", "58ee30cb6cb074dc066b7e8dfc78d8e2b1a9e97a48e39fedbace65c547703d80"),
    "sns-wasm": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "394b936be4af54ad27c1eb44537202549ad8c23445b34f08d4db1ae9e983ed01"),
    "swap": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "67f64e705afd70c0de03529a8b914f122b3fb8920d9e9d81e357b8b5e2a4d10a"),
    "sns_root": ("e790c6636115482db53ca3daa2f1900202ab04cf", "12b6bba135b8bcff8a1384f15d202dd4f6e7bbbf0554994d5da4949125b6fdaa"),
    "sns_governance": ("a9a67996f7a5f0c4e95a697fafcad6b15a5aae62", "d806d992ccd7f4f6ac0fe9faaed19f2a7b806f2b8136ba5a278fe1d093defc25"),
    "sns_index": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "110352d412a97dce090dd902e9dbdc874211d0e7a5179b6814ec1694e45a2807"),
    "sns_ledger": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "26de3e745b0e98cc83850ebf0f8fd1a574905bf7c73d52fcf61ee3f35e4875e1"),
    "sns_archive": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "ea2df4e0e3f4e5e91d43baf281728b2443ab3236ba473d78913cfbe2b5763d3c"),
    "ckbtc_index": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "110352d412a97dce090dd902e9dbdc874211d0e7a5179b6814ec1694e45a2807"),
    "ckbtc_ledger": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "26de3e745b0e98cc83850ebf0f8fd1a574905bf7c73d52fcf61ee3f35e4875e1"),
    "cketh_index": ("b43280208c32633a29657a1051660324e88a373d", "23b3ee69f3ca906a85b5cf4668a487d9519095121d8d4ccda7a3da4369238311"),
    "cketh_ledger": ("b43280208c32633a29657a1051660324e88a373d", "d58fc4d707861d93e71a2c5b39353bee703942a94d2f400a6da1cd6a0211c589"),
}

def canister_url(git_commit_id, filename):
    return "https://download.dfinity.systems/ic/{git_commit_id}/canisters/{filename}".format(
        git_commit_id = git_commit_id,
        filename = filename,
    )

def mainnet_core_nns_canisters():
    """
    Provides Bazel targets for the **core** NNS canisters that are currently deployed to the mainnet.

    This includes: Lifeline, Root, Registry, Governance, ICP Ledger (Index, Archive), CMC, GTC, SNS-W.
    """

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["registry"]
    http_file(
        name = "mainnet_nns_registry_canister",
        downloaded_file_path = "registry-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "registry-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["governance"]
    http_file(
        name = "mainnet_nns_governance_canister",
        downloaded_file_path = "governance-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "governance-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ledger"]
    http_file(
        name = "mainnet_icp_ledger_canister",
        downloaded_file_path = "ledger-canister_notify-method.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ledger-canister_notify-method.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["archive"]
    http_file(
        name = "mainnet_icp_ledger-archive-node-canister",
        downloaded_file_path = "ledger-archive-node-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ledger-archive-node-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["index"]
    http_file(
        name = "mainnet_icp_index_canister",
        downloaded_file_path = "ic-icp-index-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icp-index-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["root"]
    http_file(
        name = "mainnet_nns_root-canister",
        downloaded_file_path = "root-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "root-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["lifeline"]
    http_file(
        name = "mainnet_nns_lifeline_canister",
        downloaded_file_path = "lifeline-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "lifeline_canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["genesis-token"]
    http_file(
        name = "mainnet_nns_genesis-token-canister",
        downloaded_file_path = "genesis-token-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "genesis-token-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["cycles-minting"]
    http_file(
        name = "mainnet_nns_cycles-minting-canister",
        downloaded_file_path = "cycles-minting-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "cycles-minting-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns-wasm"]
    http_file(
        name = "mainnet_nns_sns-wasm-canister",
        downloaded_file_path = "sns-wasm-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "sns-wasm-canister.wasm.gz"),
    )

def mainnet_sns_canisters():
    """
    Provides Bazel targets for the latest SNS canisters published to the mainnet SNS-W.

    This includes: Root, SNS Governance, Swap, SNS Ledger (Index, Archive).
    """

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns_root"]
    http_file(
        name = "mainnet_sns-root-canister",
        downloaded_file_path = "sns-root-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "sns-root-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns_governance"]
    http_file(
        name = "mainnet_sns-governance-canister",
        downloaded_file_path = "sns-governance-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "sns-governance-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["swap"]
    http_file(
        name = "mainnet_sns-swap-canister",
        downloaded_file_path = "sns-swap-canister.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "sns-swap-canister.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns_ledger"]
    http_file(
        name = "mainnet_ic-icrc1-ledger",
        downloaded_file_path = "ic-icrc1-ledger.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-ledger.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns_archive"]
    http_file(
        name = "mainnet_ic-icrc1-archive",
        downloaded_file_path = "ic-icrc1-archive.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-archive.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["sns_index"]
    http_file(
        name = "mainnet_ic-icrc1-index-ng",
        downloaded_file_path = "ic-icrc1-index-ng.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-index-ng.wasm.gz"),
    )

def mainnet_fi_canisters():
    """
    Provides Bazel targets for canisters published to the mainnet for use in testing by the FI team.

    This includes: ckBTC (64-bit tokens), ckETH (256-bit tokens).
    """

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ckbtc_ledger"]
    http_file(
        name = "mainnet_ckbtc-ledger",
        downloaded_file_path = "ic-icrc1-ledger.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-ledger.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ckbtc_index"]
    http_file(
        name = "mainnet_ckbtc-index-ng",
        downloaded_file_path = "ic-icrc1-index-ng.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-index-ng.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["cketh_ledger"]
    http_file(
        name = "mainnet_cketh-ledger",
        downloaded_file_path = "ic-icrc1-ledger-u256.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-ledger-u256.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["cketh_index"]
    http_file(
        name = "mainnet_cketh-index-ng",
        downloaded_file_path = "ic-icrc1-index-ng-u256.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-index-ng-u256.wasm.gz"),
    )
