"""
For now, this just defines how large compressed SNS canister WASMs are allowed to be,
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
    "sns-governance-canister.wasm.gz": 19,
    "sns-governance-canister_test.wasm.gz": 19,
    "sns-root-canister.wasm.gz": 5,
    "sns-swap-canister.wasm.gz": 8,
}
