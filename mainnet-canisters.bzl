"""
This module defines Bazel targets for the mainnet versions of the core NNS, SNS, and ck canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("87343a880050ca72b1361138535211f5770dd52e", "8665830c50c9a0dddd996008e537d060a380ac7b6c22237679bd0cecc4ee1044"),
    "ledger": ("6dcfafb491092704d374317d9a72a7ad2475d7c9", "4fe38a91a3130e9d8b39e3413ae3b3f46c40d3fbd507df1b6092f962d970a7ea"),
    "archive": ("b43280208c32633a29657a1051660324e88a373d", "db0f094005a0e84e243f8f300236be879dcefa412c2fd36d675390caa689d88d"),
    "index": ("b43280208c32633a29657a1051660324e88a373d", "62bbbada301838ad0f6e371415be990ce70e36c6f11267d4ba9fac8ff09aa32d"),
    "root": ("a0207146be211cdff83321c99e9e70baa62733c7", "c280a25dc565f8a42429cb5b969906c4c5a789381e98f6e11c247c91c4dfaac5"),
    "registry": ("87343a880050ca72b1361138535211f5770dd52e", "57c72469f01fd6ea8b5c5a962a1fed9b4ad550bbebdae38c29d5ad330c25c724"),
    "lifeline": ("a0207146be211cdff83321c99e9e70baa62733c7", "76978515223287ece643bc7ca087eb310412b737e2382a73b8ae55fcb458da5b"),
    "genesis-token": ("cf237434877b39d0a94fb5ef84b13ea576a225ac", "31d91cbdfa6e1aae4cc4fee4f611e25f33922bd3d336f4cdc97d511e03b264a7"),
    "cycles-minting": ("77f48ae63af09b6538b1bf33d3accc3bc74d14f8", "3260e795bd3e446a189539ce89d44cb29f7d196b92cdd2e2c75571c062ef1e50"),
    "sns-wasm": ("87343a880050ca72b1361138535211f5770dd52e", "6dd00ebe425ba360be161c880ce3a3b3cda5a3738d6b323a9fd0366debf590ce"),
    "swap": ("87343a880050ca72b1361138535211f5770dd52e", "4ea01d425cd9c6c0a2c4988af03710d7c2377527eb0375067c69a9baff9963f2"),
    "sns_root": ("db5901a6e90b718918978ae5167b9c98d5aa7ab6", "d93e219b1c7f50098da1e4b19dae3e803014f7450e4fb61de5a0dc46dd94d6e1"),
    "sns_governance": ("db5901a6e90b718918978ae5167b9c98d5aa7ab6", "b80737a35a19cd3e06af3b89eabaeeba901726afa84bc108117cff6f266d55b4"),
    "sns_index": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "612410c71e893bb64772ab8131d77264740398f3932d873cb4f640fc257f9e61"),
    "sns_ledger": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "a170bfdce5d66e751a3cc03747cb0f06b450af500e75e15976ec08a3f5691f4c"),
    "sns_archive": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "9476aa71bcee621aba93a3d7c115c543f42c543de840da3224c5f70a32dbfe4d"),
    "ck_btc_index": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "612410c71e893bb64772ab8131d77264740398f3932d873cb4f640fc257f9e61"),
    "ck_btc_ledger": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "a170bfdce5d66e751a3cc03747cb0f06b450af500e75e15976ec08a3f5691f4c"),
    "ck_eth_index": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "de250f08dc7e699144b73514f55fbbb3a3f8cd97abf0f7ae31d9fb7494f55234"),
    "ck_eth_ledger": ("d4ee25b0865e89d3eaac13a60f0016d5e3296b31", "e6072806ae22868ee09c07923d093b1b0b687dba540d22cfc1e1a5392bfcca46"),
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

def mainnet_ck_canisters():
    """
    Provides Bazel targets for the latest ckBTC and ckETH canisters published to the mainnet fiduciary subnet.
    """

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ck_btc_ledger"]
    http_file(
        name = "mainnet_ckbtc_ic-icrc1-ledger",
        downloaded_file_path = "ic-icrc1-ledger.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-ledger.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ck_btc_index"]
    http_file(
        name = "mainnet_ckbtc-index-ng",
        downloaded_file_path = "ic-icrc1-index-ng.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-index-ng.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ck_eth_ledger"]
    http_file(
        name = "mainnet_cketh_ic-icrc1-ledger-u256",
        downloaded_file_path = "ic-icrc1-ledger-u256.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-ledger-u256.wasm.gz"),
    )

    git_commit_id, sha256 = CANISTER_NAME_TO_WASM_METADATA["ck_eth_index"]
    http_file(
        name = "mainnet_cketh-index-ng",
        downloaded_file_path = "ic-icrc1-index-ng-u256.wasm.gz",
        sha256 = sha256,
        url = canister_url(git_commit_id, "ic-icrc1-index-ng-u256.wasm.gz"),
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
