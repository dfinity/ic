#!/usr/bin/env bash

set -euo pipefail

CHECK_NETWORK_SCRIPT="${1:-./check-network.sh}"
CHECK_HARDWARE_SCRIPT="${2:-./check-hardware.sh}"

# ------------------------------------------------------------------------------
# Override "source" for test environment.
# ------------------------------------------------------------------------------
function source() {
    if [[ "$1" == "/opt/ic/bin/config.sh" || "$1" == "/opt/ic/bin/functions.sh" ]]; then
        echo "MOCKED: ignoring source of '$1' (file not present in test environment)"
        return
    fi
    builtin source "$1"
}

# ------------------------------------------------------------------------------
# Mocked Functions
# ------------------------------------------------------------------------------

function log_and_halt_installation_on_error() {
    if [ "$1" != "0" ]; then
        echo "ERROR encountered: $2"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Unit tests for check-network.sh
# ------------------------------------------------------------------------------

function test_validate_domain_name() {
    declare -A test_cases=(
        ["example.com"]=0
        ["node1.example.com"]=0
        ["example-.com"]=1
        ["example."]=1
        ["&BadDOMAIN.com"]=1
    )

    for domain in "${!test_cases[@]}"; do
        expected="${test_cases[$domain]}"
        echo "Running test for domain: $domain"
        domain_name="$domain"

        if ( validate_domain_name ); then
            if [[ "$expected" -eq 0 ]]; then
                echo "  PASS: valid domain: $domain"
            else
                echo "  FAIL: domain ($domain) validation was expected to fail but didn't"
                exit 1
            fi
        else
            if [[ "$expected" -eq 1 ]]; then
                echo "  PASS: domain ($domain) validation failed as expected"
            else
                echo "  FAIL: invalid domain ($domain) was incorrectly marked as valid"
                exit 1
            fi
        fi
    done
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

function test_verify_cpu_gen1_failure() {
    echo "Running test: test_verify_cpu_gen1_failure"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "Invalid CPU", "capabilities": {"sev": "false"}},
      {"id": "cpu:1", "product": "Invalid CPU", "capabilities": {"sev": "false"}}
    ]'
    get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    nproc() { echo 64; }
    HARDWARE_GENERATION="1"

    if ! (verify_cpu); then
        echo "  PASS: verify_cpu for Gen1 failed as expected"
    else
        echo "  FAIL: verify_cpu for Gen1 passed unexpectedly"
        exit 1
    fi
}

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

function test_verify_cpu_gen2_failure() {
    echo "Running test: test_verify_cpu_gen2_failure"
    FAKE_CPU_JSON='[
      {"id": "cpu:0", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "false"}},
      {"id": "cpu:1", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "false"}}
    ]'
    get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    nproc() { echo 64; }
    HARDWARE_GENERATION="2"

    if ! (verify_cpu); then
        echo "  PASS: verify_cpu for Gen2 failed as expected"
    else
        echo "  FAIL: verify_cpu for Gen2 passed unexpectedly"
        exit 1
    fi
}

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

function test_verify_memory_failure() {
    echo "Running test: test_verify_memory_failure"
    function lshw() {
        if [[ "$*" == *"-class memory"* ]]; then
            # Return insufficient memory size
            echo '[{"id": "memory", "size": 100000000000}]'
            return 0
        fi
        return 1
    }
    if ! (verify_memory); then
        echo "  PASS: verify_memory failed as expected with insufficient memory"
    else
        echo "  FAIL: verify_memory passed unexpectedly with insufficient memory"
        exit 1
    fi
}

function test_verify_deployment_path_warning() {
    echo "Running test: test_verify_deployment_path_warning"
    HARDWARE_GENERATION="2"
    function sleep() {
        echo "Sleep skipped for test"
    }
    output=$(verify_deployment_path 2>&1)
    if [[ "$output" == *"WARNING: Gen2 hardware detected"* ]]; then
        echo "  PASS: verify_deployment_path warned as expected"
    else
        echo "  FAIL: verify_deployment_path did not warn as expected"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Load scripts WITHOUT executing main() function.
# ------------------------------------------------------------------------------
for script in "${CHECK_NETWORK_SCRIPT}" "${CHECK_HARDWARE_SCRIPT}"; do
    if [[ -f "${script}" ]]; then
        tmpfile=$(mktemp)
        sed '/^main$/d' "${script}" >"${tmpfile}"
        source "${tmpfile}"
        rm "${tmpfile}"
    fi
done

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
test_verify_cpu_gen1_failure
test_verify_cpu_gen2
test_verify_cpu_gen2_failure
test_verify_memory_success
test_verify_memory_failure
test_verify_deployment_path_warning
echo
echo "PASSED check-hardware unit tests"
echo

echo
echo "All tests passed."
