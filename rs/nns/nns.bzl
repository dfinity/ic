"""
For now, this just defines how large compressed NNS canister WASMs are allowed to be,
but other things could be added here later.
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

CANISTER_NAME_TO_MAX_COMPRESSED_WASM_SIZE_E5_BYTES = {
    "cycles-minting-canister.wasm.gz": 6,
    "genesis-token-canister.wasm.gz": 3,
    "governance-canister.wasm.gz": 20,
    "governance-canister_test.wasm.gz": 22,
    "registry-canister.wasm.gz": 14,
    "root-canister.wasm.gz": 5,
}
