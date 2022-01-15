#!/usr/bin/env bash

# Prepare 3rd-party dependencies for the rosetta-tests.
#
# Usage(s):
#
#    1. As a preparatory step in an existing shell. For example:
#
#       $ . ./prepare-rosetta-deps.sh
#       $ ./run-farm-based-system-tests.sh --suite rosetta
#
#       Note: This changes the $PATH variable in the current shell.
#
#
#    2. As a wrapper:
#       $ ./prepare-rosetta-deps.sh ./run-farm-based-system-tests.sh --suite rosetta
#

set -eEou pipefail

GREEN='\033[1;32m'
NC='\033[0m'

function log() {
    echo -e "${GREEN}Rosetta Tests $(date --iso-8601=seconds): $1${NC}"
}

# Download and adjust PATH if necessary
if ! command -v rosetta-cli &>/dev/null; then
    log "rosetta-cli not present, will download it ..."
    if [ -z "$*" ]; then
        log "Note: Running as a preparatory script (3rd party downloads will *not* be deleted after this script) ..."
    else
        log "Note: Running as a wrapper script (3rd party downloads will be deleted after this script) ..."
    fi
    set -x
    ROSETTA_CLI_DIR="$(mktemp -d)/rosetta-cli"
    ROSETTA_CLI_VERSION="0.6.7"
    BASE_URL="https://github.com/coinbase/rosetta-cli/releases/download/"
    mkdir -p "${ROSETTA_CLI_DIR}" && cd "${ROSETTA_CLI_DIR}"
    curl -sSL "${BASE_URL}v${ROSETTA_CLI_VERSION}/rosetta-cli-${ROSETTA_CLI_VERSION}-linux-amd64.tar.gz" | tar -xzv
    mv "rosetta-cli-${ROSETTA_CLI_VERSION}-linux-amd64" rosetta-cli
    PATH=$PATH:"$ROSETTA_CLI_DIR"
    cd -
    set +x
fi

"$@"

if [ -n "$*" ] && [ -n "${ROSETTA_CLI_DIR:-}" ]; then
    set -x
    rm -rf "${ROSETTA_CLI_DIR}"
    set +x
fi
