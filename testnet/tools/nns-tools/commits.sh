#!/bin/bash
set -euo pipefail

# This is the V1 method of maintaining the set of mainnet SNS canister commits.
# In the future, the git hash could be returned in the response from SNS-WASM get_latest_sns_version_pretty.
# Alternatively, we could use the list_proposals API on NNS Governance to filter for the proposals of this type
# and search in the output for each canister's git hash.

SNS_WASM_COMMIT="7012a3ef8d807d5a8ee064fa7447f14a4b49e278"
SNS_SWAP_COMMIT="cffea827561a47da22dda77dab1cf61feb0437f8"
SNS_GOVERNANCE_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_ROOT_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_ARCHIVE_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_INDEX_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_LEDGER_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
