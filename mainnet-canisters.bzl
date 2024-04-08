"""
This module defines Bazel targets for the mainnet versions of the core NNS and SNS canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("d9e4d6e91c3675903d7b74b6e097d8f12f41ace3", "7f2a63edf204ff9e8fbb263f927c893e6ddb0c1df6e783a1eaf0d78d63162f2f"),
    "ledger": ("98eb213581b239c3829eee7076bea74acad9937b", "aca61e669e737133b552d0f1ddafc40299f3260daf8f57e352774b17aa82bbc1"),
    "archive": ("acd7e2928237a8e8bc1aa5e73efd47c8a8dfb556", "569d498b638668733953a756f4a417533e1f513d1d41d55960abcd2f160d2aad"),
    "root": ("7a3db052ed4c3306272ed372039d9775f189c0bc", "c18561e245a42b28add7e36d8fdd51affed75fc3e855f01d466354c9dd222f88"),
    "lifeline": ("87f48a595b6f666fbc7fe6ad4081aa98fd113d12", "6d3029dcd359f80cd64bb68bbc8bd95b810b08bd29b9ef1054118a5285f2abc5"),
    "genesis-token": ("87f48a595b6f666fbc7fe6ad4081aa98fd113d12", "dd71862512af57e938e01810be016e17431912d9ca0ea3952bc04015eb02acc4"),
    "cycles-minting": ("d9e4d6e91c3675903d7b74b6e097d8f12f41ace3", "3e6362c49107d856752f7934101591b138d69dc938a90ce7447514dcbf369524"),
    "sns-wasm": ("d9e4d6e91c3675903d7b74b6e097d8f12f41ace3", "f8277aa817c4a14d821c909fd8c339fc361e5d60aa295a49056e56337c015cf6"),
    "swap": ("48e7e1f072c259810236488ff770c809f362fb63", "9531eafc54069e835636011e17a19a4709a3123c6a4d2f56c58a44c3cc31e1d6"),
    "sns_root": ("7a3db052ed4c3306272ed372039d9775f189c0bc", "8d479572f739d13ba05f1d98b834edb4bbd3f96abab90397a4701e6ed3142829"),
}

# Release 2024-03-26
# Public Announcement: https://forum.dfinity.org/t/nns-updates-2024-03-25/28828
COMMIT_ID = "c70bc267dfdc1143d8af70b32a4b51619aa71b80"
CANISTER_NAME_TO_WASM_METADATA.update({
    "registry": (COMMIT_ID, "9ffc0d513192187f02ecbab7131929292f14e7286b144c988550400013bdcf62"),  # https://dashboard.internetcomputer.org/proposal/128810
    "sns_governance": (COMMIT_ID, "2ed70d057e0a970e7e46010324fd38147176f8c943f412a44fa2cb3bf75eda90"),  # https://dashboard.internetcomputer.org/proposal/128811
    "sns_index": (COMMIT_ID, "aeb1392244cb04edbc33d0b3078144c09844081af438e338ffdf08573fb731fe"),  # https://dashboard.internetcomputer.org/proposal/128812
    "sns_ledger": (COMMIT_ID, "385d537b3add5b023e1bef5f69f52d9fb1388d9e1653ca74edbd39c50fa2b5dc"),  # https://dashboard.internetcomputer.org/proposal/128813
    "sns_archive": (COMMIT_ID, "d7a4fe77f1675b50dbf5c37ad074ec7182829bb1592176963fe0a3e2614abc00"),  # https://dashboard.internetcomputer.org/proposal/128814
})

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
