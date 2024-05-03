"""
This module defines Bazel targets for the mainnet versions of the core NNS and SNS canisters.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# WASM metadata is a 2-tuple of git commit ID and WASM hash.
CANISTER_NAME_TO_WASM_METADATA = {
    "governance": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "91b6a1fa1c781d278bff3ed3a81961295631f31cf07e69139e5522aeb66c879a"),
    "ledger": ("98eb213581b239c3829eee7076bea74acad9937b", "aca61e669e737133b552d0f1ddafc40299f3260daf8f57e352774b17aa82bbc1"),
    "archive": ("8d80b3b3703988645a604641f8d600d525bb5c21", "d7229caa5106454413c5382437cfb0864dedc36058611111debf94da0258998b"),
    "index": ("463296c0bc82ad5999b70245e5f125c14ba7d090", "8157f5cba913d9db25a2c54ebf823d4edcc50cce00b97a18e5d33c2f73e59c93"),
    "root": ("d7ddd2969837fc6c9c0b86d331f7bc61e9e78bd1", "4607bb1c0742a52449a7c66f7d90681c2d876372a49a8ed474852bcdef144001"),
    "registry": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "c980ac57375a4b7c7ea1ea27f09c65ec1020832cfc9132a69667850ae487907d"),
    "lifeline": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "614d7d418c4eaa9984b6c3f4afe2d1e45b2f110369edcc2dc767792181742348"),
    "genesis-token": ("87f48a595b6f666fbc7fe6ad4081aa98fd113d12", "dd71862512af57e938e01810be016e17431912d9ca0ea3952bc04015eb02acc4"),
    "cycles-minting": ("d9e4d6e91c3675903d7b74b6e097d8f12f41ace3", "3e6362c49107d856752f7934101591b138d69dc938a90ce7447514dcbf369524"),
    "sns-wasm": ("35e4f2c583b0657aa730740b5c8aca18a8718b8e", "2bdb5a6dc5ec5b9c7a9a57cb6330164de8a438539fa87526644de792e687329b"),
    "swap": ("d7ddd2969837fc6c9c0b86d331f7bc61e9e78bd1", "a4b4008c9ae41e3a06cd0a81b74542270184024d8ca5d71a7f71137aa7e575e5"),
    "sns_root": ("d7ddd2969837fc6c9c0b86d331f7bc61e9e78bd1", "a5c86d0fb4f487065d4dc11c743123031c735f31e3d42ca3405dfdbbd863e8e9"),
    "sns_governance": ("28acff64b0ddafa9cb71f6c8004619927efb101b", "718068f22d7635a133b4398327210a9ff64675fc16599139df6931544472d653"),
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
