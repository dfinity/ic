"""
This just contains some constants that tell tests in //publish/canisters how large our gzipped
WASMs are allowed to be.
"""

# How these limits were chosen:
#
#   1. Temporarily set value to "0".
#   2. Run the test: bazel test //publish/canisters:all
#   3. Fail message reports size it sees.
#   4. Pick a number that gives at least 20% headroom.
#
# This way, there is some room to grow, but an alarm eventually gets triggered after a "significant"
# amount of growth happens.

NNS_CANISTERS_MAX_SIZE_COMPRESSED_E5_BYTES = {
    "cycles-minting-canister.wasm.gz": "5",
    "genesis-token-canister.wasm.gz": "2",
    "governance-canister.wasm.gz": "10",
    "governance-canister_test.wasm.gz": "10",
    "governance-mem-test-canister.wasm.gz": "2",
    "registry-canister.wasm.gz": "10",
    "root-canister.wasm.gz": "4",
}

SNS_CANISTERS_MAX_SIZE_COMPRESSED_E5_BYTES = {
    "sns-governance-canister.wasm.gz": "8",
    "sns-governance-canister_test.wasm.gz": "8",
    "sns-root-canister.wasm.gz": "3",
    "sns-swap-canister.wasm.gz": "6",
}
