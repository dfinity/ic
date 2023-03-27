#!/bin/bash
set -euo pipefail

# This is the V1 method of maintaining the set of mainnet SNS canister commits.
# In the future, the git hash could be returned in the response from SNS-WASM get_latest_sns_version_pretty.
# Alternatively, we could use the list_proposals API on NNS Governance to filter for the proposals of this type
# and search in the output for each canister's git hash.

SNS_WASM_COMMIT="9bb8f35cccd013b38657c67964c39d48fac6353f"
SNS_SWAP_COMMIT="932c1bfc04728783a815e0867b579c1eb26df99d"
SNS_GOVERNANCE_COMMIT="8573ad55864cd396e963ab03668cc4bf634375c4"
SNS_ROOT_COMMIT="8573ad55864cd396e963ab03668cc4bf634375c4"
SNS_ARCHIVE_COMMIT="822f933e7db6b3f843401245d0bf814632ed4084"
SNS_INDEX_COMMIT="9bb8f35cccd013b38657c67964c39d48fac6353f"
SNS_LEDGER_COMMIT="822f933e7db6b3f843401245d0bf814632ed4084"
