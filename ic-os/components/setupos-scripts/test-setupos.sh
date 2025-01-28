#!/usr/bin/env bash

set -euo pipefail

CHECK_NETWORK_SCRIPT="${1:-./check-network.sh}"

# ------------------------------------------------------------------------------
# Override "source" so that sourcing /opt/ic/bin/config.sh and /opt/ic/bin/functions.sh
# does not fail in our test environment.
# ------------------------------------------------------------------------------
function source() {
    if [[ "$1" == "/opt/ic/bin/config.sh" || "$1" == "/opt/ic/bin/functions.sh" ]]; then
        echo "MOCKED: ignoring source of '$1' (file not present in test environment)"
        return
    fi
    builtin source "$1"
}

# ------------------------------------------------------------------------------
# Mocked out functions
# ------------------------------------------------------------------------------

function log_and_halt_installation_on_error() {
    local exit_code="$1"
    return "${exit_code}"
}

function log_start() {
    local script="${1}"
}

function log_end() {
    local script="${1}"
}

# ------------------------------------------------------------------------------
# Unit tests
# ------------------------------------------------------------------------------

function test_validate_domain_name() {
    echo "Running test: test_validate_domain_name_valid"
    domain_name="example.com"
    # If domain_name is valid, validate_domain_name should never call
    # log_and_halt_installation_on_error, so it should exit 0.
    if validate_domain_name; then
        echo "  PASS: valid domain: $domain_name"
    else
        echo "  FAIL: valid domain: domain_name"
        exit 1
    fi

    echo "Running test: test_validate_domain_name_invalid"
    domain_name="example."
    if ! validate_domain_name; then
        echo "  PASS: domain $domain_name validation failed as expected"
    else
        echo "  FAIL: domain $domain_name validation was expected to fail but didn't"
        exit 1
    fi
    domain_name="&BadDOMAIN.com"
    if ! validate_domain_name; then
        echo "  PASS: domain $domain_name validation failed as expected"
    else
        echo "  FAIL: domain $domain_name validation was expected to fail but didn't"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Run tests
# ------------------------------------------------------------------------------
source "${CHECK_NETWORK_SCRIPT}"

test_validate_domain_name

echo
echo "All tests passed."