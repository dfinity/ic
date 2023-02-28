#!/bin/bash

# Set a few useful variables
LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/" &>/dev/null && pwd)
NNS_TOOLS_DIR=$LIB_DIR/..
# Needed because otherwise we get conflicts between two users running scripts on same machine (tmp directory is shared)
MY_DOWNLOAD_DIR="/tmp/$(whoami)_nns_tools_tmp"
mkdir -p $MY_DOWNLOAD_DIR

source "$NNS_TOOLS_DIR/../lib.sh"

source "$LIB_DIR/boundary_node.sh"
source "$LIB_DIR/canister_wasms.sh"
source "$LIB_DIR/canisters.sh"
source "$LIB_DIR/functions.sh"
source "$LIB_DIR/installers.sh"
source "$LIB_DIR/proposals.sh"
source "$LIB_DIR/topology.sh"
source "$LIB_DIR/util.sh"
