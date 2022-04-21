#!/usr/bin/env bash

# Tools to copy ic executables into the build process.

set -eo pipefail

declare -a IC_EXECUTABLES=(orchestrator replica canister_sandbox sandbox_launcher vsock_agent state-tool ic-consensus-pool-util ic-crypto-csp ic-regedit ic-btc-adapter ic-canister-http-adapter)

# Install IC executables from source to target
#
# Arguments:
# - $1: Source directory for executables
# - $2: Target directory for executables
#
# Will install all required executables to the location
# from where they will be picked up by disk image build.
# Executables are stripped if needed and only copied if
# modified relative to their originals.
function install_executables() {
    local SRCDIR="$1"
    local TGTDIR="$2"
    for EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
        if [ ! -f "${TGTDIR}/${EXECUTABLE}" -o "${SRCDIR}/${EXECUTABLE}" -nt "${TGTDIR}/${EXECUTABLE}" ]; then
            echo "Install and strip ${EXECUTABLE}"
            cp "${SRCDIR}/${EXECUTABLE}" "${TGTDIR}/${EXECUTABLE}"
            if [[ "${EXECUTABLE}" =~ ^(replica|canister_sandbox)$ ]]; then
                echo "not stripping ${EXECUTABLE}"
            else
                echo "stripping ${EXECUTABLE}"
                strip "${TGTDIR}/${EXECUTABLE}"
            fi
        fi
    done
}

# Verify that all files requires for build have been put into suitable place.
# This avoids "broken builds" where the build works just fine, but
# the resulting image lacks things and is not bootable.
#
# Arguments:
# - $1: Target directory to verify
function verify_before_build() {
    local TGTDIR="$1"
    for EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
        if [ ! -f "${TGTDIR}/opt/ic/bin/${EXECUTABLE}" ]; then
            echo "Missing executable ${EXECUTABLE} -- build will not succeed."
            exit 1
        fi
    done
    if [ ! -f "${TGTDIR}/opt/ic/share/version.txt" -o ! -f "${TGTDIR}/boot/version.txt" ]; then
        echo "Missing version.txt -- build will not succeed."
        exit 1
    fi
}
