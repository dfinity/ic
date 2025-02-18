#!/usr/bin/env bash

set -euo pipefail

CHECK_NETWORK_SCRIPT="${1:-./check-network.sh}"
CHECK_HARDWARE_SCRIPT="${2:-./check-hardware.sh}"

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
# Unit tests for check-network.sh
# ------------------------------------------------------------------------------

function test_validate_domain_name() {
    echo "Running test: test_validate_domain_name_valid"
    domain_name="example.com"
    # If domain_name is valid, validate_domain_name should never call
    # log_and_halt_installation_on_error, so it should exit 0.
    if validate_domain_name; then
        echo "  PASS: valid domain: $domain_name"
    else
        echo "  FAIL: valid domain: $domain_name"
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
# Unit tests for check-hardware.sh
# ------------------------------------------------------------------------------

function test_detect_hardware_generation_gen1() {
    echo "Running test: test_detect_hardware_generation_gen1"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}}
    ]'
    function get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    HARDWARE_GENERATION=""
    detect_hardware_generation
    if [[ "$HARDWARE_GENERATION" == "1" ]]; then
      echo "  PASS: Gen1 hardware detected"
    else
      echo "  FAIL: Gen1 hardware not detected as expected"
      exit 1
    fi
}

function test_detect_hardware_generation_gen2() {
    echo "Running test: test_detect_hardware_generation_gen2"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}}
    ]'
    function get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    HARDWARE_GENERATION=""
    detect_hardware_generation
    if [[ "$HARDWARE_GENERATION" == "2" ]]; then
      echo "  PASS: Gen2 hardware detected"
    else
      echo "  FAIL: Gen2 hardware not detected as expected"
      exit 1
    fi
}

function test_verify_cpu_gen1() {
    echo "Running test: test_verify_cpu_gen1"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}}
    ]'
    function get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    function nproc() { echo 64; }
    HARDWARE_GENERATION="1"
    verify_cpu
    echo "  PASS: verify_cpu for Gen1 passed"
}

# Test verify_cpu for Gen2.
function test_verify_cpu_gen2() {
    echo "Running test: test_verify_cpu_gen2"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}}
    ]'
    function get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    function nproc() { echo 70; }
    HARDWARE_GENERATION="2"
    verify_cpu
    echo "  PASS: verify_cpu for Gen2 passed"
}

# Test memory verification by simulating a memory JSON with sufficient size.
function test_verify_memory_success() {
    echo "Running test: test_verify_memory_success"
    function lshw() {
      if [[ "$*" == *"-class memory"* ]]; then
         echo '[{"id": "memory", "size": 600000000000}]'
         return 0
      fi
      return 1
    }
    verify_memory
    echo "  PASS: verify_memory passed with sufficient memory"
}

# ------------------------------------------------------------------------------
# Load scripts WITHOUT executing main() function.
# ------------------------------------------------------------------------------
if [[ -f "${CHECK_NETWORK_SCRIPT}" ]]; then
    tmpfile=$(mktemp)
    sed '/^main$/d' "${CHECK_NETWORK_SCRIPT}" > "${tmpfile}"
    source "${tmpfile}"
    rm "${tmpfile}"
fi
if [[ -f "${CHECK_HARDWARE_SCRIPT}" ]]; then
    tmpfile=$(mktemp)
    sed '/^main$/d' "${CHECK_HARDWARE_SCRIPT}" > "${tmpfile}"
    source "${tmpfile}"
    rm "${tmpfile}"
fi

# ------------------------------------------------------------------------------
# Run all tests
# ------------------------------------------------------------------------------

echo
echo "Running check-network.sh unit tests..."
test_validate_domain_name
echo
echo "PASSED check-network unit tests"
echo

echo
echo "Running check-hardware.sh unit tests..."
test_detect_hardware_generation_gen1
test_detect_hardware_generation_gen2
test_verify_cpu_gen1
test_verify_cpu_gen2
test_verify_memory_success
echo
echo "PASSED check-network unit tests"
echo

echo
echo "All tests passed."
