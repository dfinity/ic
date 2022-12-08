#!/bin/bash
set -euo pipefail

# This is the V1 method of maintaining the set of mainnet SNS canister commits.
# In the future, the git hash could be returned in the response from SNS-WASM get_latest_sns_version_pretty.
# Alternatively, we could use the list_proposals API on NNS Governance to filter for the proposals of this type
# and search in the output for each canister's git hash.

SNS_WASM_COMMIT="7012a3ef8d807d5a8ee064fa7447f14a4b49e278"
SNS_SWAP_COMMIT="c9b2f9653afc2da47e5bd527c192090b860acbf0"
SNS_GOVERNANCE_COMMIT="090276896af7c5eaa9d9dcbb9af45fe957d0a99b"
SNS_ROOT_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_ARCHIVE_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_INDEX_COMMIT="1fc0208b9aeed0554b1be2711605e5b54ace9d6a"
SNS_LEDGER_COMMIT="d4d9551c4d11b56f6c98e7815eabb12550d3a6db"
