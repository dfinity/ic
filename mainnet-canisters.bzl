"""
This module defines Bazel targets for the mainnet versions of the core NNS, SNS, and ck canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("c7d517db67fde740f5e3338c86e95b4ec8beb00a", "e1dabec0709deafdf79a8889eff8c823a2e19000809379fdef1ff377249296b2"),
    "ledger": ("2bdfdc54ccc7ef27dd7b4f37aaea172198dce6ab", "5714a608b4c0af565c5c348e7c54e837512bc47e8f271add6bcd680ec72ef9a0"),
    "archive": ("b43280208c32633a29657a1051660324e88a373d", "db0f094005a0e84e243f8f300236be879dcefa412c2fd36d675390caa689d88d"),
    "index": ("b43280208c32633a29657a1051660324e88a373d", "62bbbada301838ad0f6e371415be990ce70e36c6f11267d4ba9fac8ff09aa32d"),
    "root": ("c7d517db67fde740f5e3338c86e95b4ec8beb00a", "ab4ee8460537c49e50e45fc0bf1aae656770b65e113b48a6a6f599ffbe4fe6e9"),
    "registry": ("1fd18580dbca83d418e1e55d490074b7195aa606", "07c584821cc2c4a7d1a23c31f2337eb66bc46dbd470e15e01c6d530e30cd7c0d"),
    "lifeline": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "614d7d418c4eaa9984b6c3f4afe2d1e45b2f110369edcc2dc767792181742348"),
    "genesis-token": ("ad5629caa17ac8a4545bc2e3cf0ecc990c9f681e", "a403f573c4426065b1a9b7b5b1a7f95c04534c6d79a06be71f1d04212b40e9de"),
    "cycles-minting": ("3b3ffedc6aa481fd9b92eefaf46beded9e51a344", "f24df747ad451a9d45fe2e98aa60b82578203fb73fc24316cd33ce98307e9f0c"),
    "sns-wasm": ("3b3ffedc6aa481fd9b92eefaf46beded9e51a344", "f4d02df832c1ef951618d954c52ee06cd6046b170d1b360563116c2a40afe643"),
    "swap": ("c7d517db67fde740f5e3338c86e95b4ec8beb00a", "20c6fe772a0f5be86fda4ceff1e8e13b5071f9a85d83d6052c61e09084b406d6"),
    "sns_root": ("c9e692e3d74692fcde77cb308039a734872ae0f0", "e872d754f37dcd31558d2bb2829e2fe7fc33f61039bf6df66e9fdc1fa9fccea8"),
    "sns_governance": ("c7d517db67fde740f5e3338c86e95b4ec8beb00a", "3feb8ff7b47f53da83235e4c68676bb6db54df1e62df3681de9425ad5cf43be5"),
    "sns_index": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0"),
    "sns_ledger": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4"),
    "sns_archive": ("3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d", "5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f"),
    "ck_btc_index": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "cac207cf438df8c9fba46d4445c097f05fd8228a1eeacfe0536b7e9ddefc5f1c"),
    "ck_btc_ledger": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "4264ce2952c4e9ff802d81a11519d5e3ffdaed4215d5831a6634e59efd72f7d8"),
    "ck_eth_index": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "8104acad6105abb069b2dbc8289692bd63c2d110127f8e91f99db51465962606"),
    "ck_eth_ledger": ("a3831c87440df4821b435050c8a8fcb3745d86f6", "e5c8a297d1c0c6d2ab2253c0280aaefd6e23fe3a8a994fc64706a1f3c3116062"),
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
