"""
This module defines Bazel targets for the mainnet versions of the core NNS and SNS canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "8f76b2de37197b3ff0ae188f1ef99ddd5bd75cb8f83fb87c2889822ece0b5576"),
    "ledger": ("b43280208c32633a29657a1051660324e88a373d", "209d01896799444a40a80ac21ac22ad23fd7abdde7d6cff0c96326d178e4c5a8"),
    "archive": ("b43280208c32633a29657a1051660324e88a373d", "db0f094005a0e84e243f8f300236be879dcefa412c2fd36d675390caa689d88d"),
    "index": ("b43280208c32633a29657a1051660324e88a373d", "62bbbada301838ad0f6e371415be990ce70e36c6f11267d4ba9fac8ff09aa32d"),
    "root": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "713f44b9d26cfc9ed2083bad954cdfcabb7de211bfc1c4fc811d8c7bb4f47d81"),
    "registry": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "f1555a94d322d5ffa024748d20a58b88b7bca756a82f5da2b3c7ef0f3cd190ea"),
    "lifeline": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "614d7d418c4eaa9984b6c3f4afe2d1e45b2f110369edcc2dc767792181742348"),
    "genesis-token": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "a403f573c4426065b1a9b7b5b1a7f95c04534c6d79a06be71f1d04212b40e9de"),
    "cycles-minting": ("b9a20425f94eb1433385a7ed0c59c41095c17b7b", "58ee30cb6cb074dc066b7e8dfc78d8e2b1a9e97a48e39fedbace65c547703d80"),
    "sns-wasm": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "394b936be4af54ad27c1eb44537202549ad8c23445b34f08d4db1ae9e983ed01"),
    "swap": ("b39f782ae9e976f6f25c8f1d75b977bd22c81507", "67f64e705afd70c0de03529a8b914f122b3fb8920d9e9d81e357b8b5e2a4d10a"),
    "sns_root": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "2c6018ca27ae077a26acb63821d20328bf1db2dc2710d9a7245cd1c4ae22d388"),
    "sns_governance": ("a9a67996f7a5f0c4e95a697fafcad6b15a5aae62", "d806d992ccd7f4f6ac0fe9faaed19f2a7b806f2b8136ba5a278fe1d093defc25"),
    "sns_index": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "110352d412a97dce090dd902e9dbdc874211d0e7a5179b6814ec1694e45a2807"),
    "sns_ledger": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "26de3e745b0e98cc83850ebf0f8fd1a574905bf7c73d52fcf61ee3f35e4875e1"),
    "sns_archive": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "ea2df4e0e3f4e5e91d43baf281728b2443ab3236ba473d78913cfbe2b5763d3c"),
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
