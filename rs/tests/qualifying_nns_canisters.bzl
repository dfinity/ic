"""
This file specifies the NNS and SNS canisters that are to be qualified for the upcoming
release. The lists below should always be empty, except on branches called `nns-qualification-$DATE`.

Notes:
- The `nns-qualification-$DATE` branches should be used for both NNS and SNS qualification.
"""

# List Network Nervous System (NNS) canisters to be qualified for the upcoming release.
#
# Assumptions:
# - List elements must be keys of `NNS_CANISTER_WASM_PROVIDERS` from /rs/tests/common.bzl
#
# Semantics:
# - Canisters in the lists below will be installed at the tip-of-the-branch version,
#   if the system test specifies `QUALIFYING_NNS_CANISTER_RUNTIME_DEPS`
# - Canisters not in the list will be installed at the latest mainnet deployment
#   versions (downloaded from the CDN).
#
# Notes:
# - Despite `sns` in its name, `sns-wasm-canister` belongs to the NNS, not SNS.
QUALIFYING_NNS_CANISTERS = []

# List Service Nervous System (SNS) canisters to be qualified for the upcoming release.
#
# Assumptions:
# - List elements must be keys of `SNS_CANISTER_WASM_PROVIDERS` from /rs/tests/common.bzl
#
# Semantics:
# - Canisters in the lists below will be installed at the tip-of-the-branch version,
#   if the system test specifies `QUALIFYING_SNS_CANISTER_RUNTIME_DEPS`
# - Canisters not in the list will be installed at the latest mainnet deployment
#   versions (downloaded from the CDN).
QUALIFYING_SNS_CANISTERS = []
