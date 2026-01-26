#!/usr/bin/env bash

set -euo pipefail

CHECK_NETWORK_SCRIPT="${1:-./check-network.sh}"
CHECK_HARDWARE_SCRIPT="${2:-./check-hardware.sh}"
FUNCTIONS_SCRIPT="${3:-./functions.sh}"

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

        if (validate_domain_name); then
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
# Parameterized unit test for check-hardware.sh
# ------------------------------------------------------------------------------

function test_detect_hardware_generation() {
    # Gen1 test
    test_detect_hardware_generation_helper 0 "type0" "1"
    test_detect_hardware_generation_helper 0 "type1" "1"
    test_detect_hardware_generation_helper 0 "type1.1" "1"
    test_detect_hardware_generation_helper 0 "type1.9" "1"
    # Gen2 test
    test_detect_hardware_generation_helper 0 "type3" "2"
    test_detect_hardware_generation_helper 0 "type3.1" "2"
    test_detect_hardware_generation_helper 0 "type3.5" "2"

    test_detect_hardware_generation_helper 1 "type5" "fail"
    test_detect_hardware_generation_helper 1 "type33" "fail"
}

function test_detect_hardware_generation_helper() {
    local expected_result="$1"
    local fake_node_reward_type="$2"
    local expected_hardware_generation="$3"
    echo "Running test: test_detect_hardware_generation for Gen${expected_hardware_generation}"

    function get_config_value() { echo "$fake_node_reward_type"; }
    HARDWARE_GENERATION=""

    if [ "$expected_result" -eq 0 ]; then
        detect_hardware_generation
        if [[ "$HARDWARE_GENERATION" == "${expected_hardware_generation}" ]]; then
            echo "  PASS: Gen${expected_hardware_generation} hardware detected"
        else
            echo "  FAIL: Gen${expected_hardware_generation} hardware not detected as expected"
            exit 1
        fi
    elif ! (detect_hardware_generation); then
        echo "  PASS: unknown node rewards type correctly caused failure"
    else
        echo "  FAIL: detect hardware generation failed unexpectedly"
        exit 1
    fi
}

function test_verify_cpu() {
    # Gen1 Success
    test_verify_cpu_helper "verify_cpu Gen1 success" "1" '[
      {"id": "cpu:0", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7302", "capabilities": {"sev": "true"}}
    ]' 64 0

    # Gen1 Failure
    test_verify_cpu_helper "verify_cpu Gen1 failure" "1" '[
      {"id": "cpu:0", "product": "Invalid CPU", "capabilities": {"sev": "false"}},
      {"id": "cpu:1", "product": "Invalid CPU", "capabilities": {"sev": "false"}}
    ]' 64 1

    # Gen2 Success
    test_verify_cpu_helper "verify_cpu Gen2 success" "2" '[
      {"id": "cpu:0", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}},
      {"id": "cpu:1", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "true"}}
    ]' 70 0

    # Gen2 Failure
    test_verify_cpu_helper "verify_cpu Gen2 failure" "2" '[
      {"id": "cpu:0", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "false"}},
      {"id": "cpu:1", "product": "AMD EPYC 7313", "capabilities": {"sev_snp": "false"}}
    ]' 64 1
}

function test_verify_cpu_helper() {
    local test_label="$1"
    local HARDWARE_GENERATION="$2"
    local FAKE_CPU_JSON="$3"
    local nproc_val="$4"
    local expected_result="$5"

    echo "Running test: ${test_label}"
    function get_cpu_info_json() { echo "$FAKE_CPU_JSON"; }
    function nproc() { echo "$nproc_val"; }

    if [ "$expected_result" -eq 0 ]; then
        if (verify_cpu); then
            echo "  PASS: ${test_label} passed"
        else
            echo "  FAIL: ${test_label} expected to pass but failed"
            exit 1
        fi
    else
        if ! (verify_cpu); then
            echo "  PASS: ${test_label} failed as expected"
        else
            echo "  FAIL: ${test_label} passed unexpectedly"
            exit 1
        fi
    fi
}

function test_verify_memory() {
    # Sufficient memory case:
    test_verify_memory_helper 600000000000 0
    # Insufficient memory case:
    test_verify_memory_helper 100000000000 1
}

function test_verify_memory_helper() {
    local memory_size="$1"
    local expected_result="$2"
    echo "Running test: test_verify_memory with memory size: $memory_size"
    function lshw() {
        if [[ "$*" == *"-class memory"* ]]; then
            echo "[{\"id\": \"memory\", \"size\": $memory_size}]"
            return 0
        fi
        return 1
    }

    if [ "$expected_result" -eq 0 ]; then
        if (verify_memory); then
            echo "  PASS: verify_memory passed with sufficient memory"
        else
            echo "  FAIL: verify_memory expected to pass with sufficient memory but failed"
            exit 1
        fi
    else
        if ! (verify_memory); then
            echo "  PASS: verify_memory failed as expected with insufficient memory"
        else
            echo "  FAIL: verify_memory passed unexpectedly with insufficient memory"
            exit 1
        fi
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
# Unit tests for functions.sh
# ------------------------------------------------------------------------------

function test_check_cmdline_var() {
    # Test parameter set to 1.
    check_cmdline_var testparm /dev/fd/3 3<<<'otherparm_quoted="abc def" testparm=1' || {
        echo "  FAIL: expected check_cmdline_var to be true with testparm=1"
        exit 1
    }

    # Test parameter set to 0.
    ! check_cmdline_var testparm /dev/fd/3 3<<<'otherparm_quoted="abc def" testparm=0' || {
        echo "  FAIL: expected check_cmdline_var to be false with testparm=0"
        exit 1
    }

    # Test parameter set (equivalent to 1).
    check_cmdline_var testparm /dev/fd/3 3<<<'otherparm_quoted="abc def" testparm' || {
        echo "  FAIL: expected check_cmdline_var to be true with testparm"
        exit 1
    }

    # Test parameter absent.
    check_cmdline_var testparm /dev/fd/3 3<<<'otherparm_quoted="abc def" notestparm' || {
        echo "  FAIL: expected check_cmdline_var to be true without testparm"
        exit 1
    }
}

# ------------------------------------------------------------------------------
# Load scripts WITHOUT executing main() function.
# ------------------------------------------------------------------------------
for script in "${CHECK_NETWORK_SCRIPT}" "${CHECK_HARDWARE_SCRIPT}" "${FUNCTIONS_SCRIPT}"; do
    if [[ -f "${script}" ]]; then
        tmpfile=$(mktemp)
        sed '/^main$/d' "${script}" >"${tmpfile}"
        source "${tmpfile}"
        rm "${tmpfile}"
    fi
done

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
test_detect_hardware_generation
test_verify_cpu
test_verify_memory
test_verify_deployment_path_warning
echo
echo "PASSED check-hardware unit tests"
echo

echo
echo "Running functions.sh unit tests..."
test_check_cmdline_var
echo
echo "PASSED functions unit tests"
echo

echo
echo "All tests passed."
