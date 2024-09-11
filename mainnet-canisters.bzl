"""
This module defines Bazel targets for the mainnet versions of the core NNS, SNS, and ck canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("cf237434877b39d0a94fb5ef84b13ea576a225ac", "f019626d0764c0574908896a08f9dae8348a81359cea3f2a18125ab40d8b399b"),
    "ledger": ("b0ade55f7e8999e2842fe3f49df163ba224b71a2", "d0ec2cdeee48e2dbee07c59dfdc3928413de86930242fef0704ab7c1be6c7664"),
    "archive": ("b43280208c32633a29657a1051660324e88a373d", "db0f094005a0e84e243f8f300236be879dcefa412c2fd36d675390caa689d88d"),
    "index": ("b43280208c32633a29657a1051660324e88a373d", "62bbbada301838ad0f6e371415be990ce70e36c6f11267d4ba9fac8ff09aa32d"),
    "root": ("a0207146be211cdff83321c99e9e70baa62733c7", "c280a25dc565f8a42429cb5b969906c4c5a789381e98f6e11c247c91c4dfaac5"),
    "registry": ("1fd18580dbca83d418e1e55d490074b7195aa606", "07c584821cc2c4a7d1a23c31f2337eb66bc46dbd470e15e01c6d530e30cd7c0d"),
    "lifeline": ("a0207146be211cdff83321c99e9e70baa62733c7", "76978515223287ece643bc7ca087eb310412b737e2382a73b8ae55fcb458da5b"),
    "genesis-token": ("cf237434877b39d0a94fb5ef84b13ea576a225ac", "31d91cbdfa6e1aae4cc4fee4f611e25f33922bd3d336f4cdc97d511e03b264a7"),
    "cycles-minting": ("77f48ae63af09b6538b1bf33d3accc3bc74d14f8", "3260e795bd3e446a189539ce89d44cb29f7d196b92cdd2e2c75571c062ef1e50"),
    "sns-wasm": ("a0207146be211cdff83321c99e9e70baa62733c7", "b85913246f0972c119d7882abac6d6a7655f9acfd8c180fd3752970a139681e7"),
    "swap": ("a0207146be211cdff83321c99e9e70baa62733c7", "3bb490d197b8cf2e7d9948bcb5d1fc46747a835294b3ffe47b882dbfa584555f"),
    "sns_root": ("a0207146be211cdff83321c99e9e70baa62733c7", "495e31370b14fa61c76bd1483c9f9ba66733793ee2963e8e44a231436a60bcc6"),
    "sns_governance": ("c7d517db67fde740f5e3338c86e95b4ec8beb00a", "3feb8ff7b47f53da83235e4c68676bb6db54df1e62df3681de9425ad5cf43be5"),
    "sns_index": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0"),
    "sns_ledger": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4"),
    "sns_archive": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f"),
    "ck_btc_index": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "cac207cf438df8c9fba46d4445c097f05fd8228a1eeacfe0536b7e9ddefc5f1c"),
    "ck_btc_ledger": ("d323465e02b84a0bc3b8c2c6fd362f6072f1a3f2", "cb5fc1cd94cb75791e8c01be3116122d779ef61c6eab41f10b60f6e79fe9f0e9"),
    "ck_eth_index": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "8104acad6105abb069b2dbc8289692bd63c2d110127f8e91f99db51465962606"),
    "ck_eth_ledger": ("d323465e02b84a0bc3b8c2c6fd362f6072f1a3f2", "e61b0c6fcf598ee1e7551cc9ee10869f6dccf685bf9af714476baefd240f9978"),
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
