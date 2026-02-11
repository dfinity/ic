#!/bin/bash

# Set a few useful variables
LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/" &>/dev/null && pwd)

# Needed because otherwise we get conflicts between two users running scripts on same machine (tmp directory is shared)
MY_DOWNLOAD_DIR="/tmp/$(whoami)_nns_tools_tmp"
mkdir -p $MY_DOWNLOAD_DIR

# Try to find utils in the environment if they're not already set
IDL2JSON=${IDL2JSON:-$(which idl2json 2>/dev/null || true)}
SNS_QUILL=${SNS_QUILL:-$(which sns-quill 2>/dev/null || true)}
IC_ADMIN=${IC_ADMIN:-$(which ic-admin 2>/dev/null || true)}
IC_WASM=${IC_WASM:-$(which ic-wasm 2>/dev/null || true)}

__dfx() {
    HOME="${DFX_HOME:-$HOME}" dfx "${@}"
}

source "$LIB_DIR/lib.sh"
source "$LIB_DIR/canister_wasms.sh"
source "$LIB_DIR/canisters.sh"
source "$LIB_DIR/constants.sh"
source "$LIB_DIR/functions.sh"
source "$LIB_DIR/installers.sh"
source "$LIB_DIR/nns_neurons.sh"
source "$LIB_DIR/proposals.sh"
source "$LIB_DIR/sns_upgrades.sh"
source "$LIB_DIR/topology.sh"
source "$LIB_DIR/util.sh"
