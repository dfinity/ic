#!/usr/bin/env bash

# Checks the HostOS metrics-proxy units against each other and against the path
# the generator actually writes.

set -euo pipefail

OVERRIDE="$1"
GENERATOR="$2"
BASE_UNIT="$3"
CONFIG_LIB_RS="$4"

GENERATOR_UNIT="generate-metrics-proxy-config.service"

fail() {
    echo "  FAIL: $*"
    exit 1
}

pass() {
    echo "  PASS: $*"
}

# The drop-in must point metrics-proxy at exactly the path the generator writes.
function test_config_path_agrees_with_generator() {
    local rust_path
    rust_path=$(sed -n 's/.*DEFAULT_HOSTOS_METRICS_PROXY_OUTPUT_PATH[^"]*"\([^"]*\)".*/\1/p' "${CONFIG_LIB_RS}")
    [[ -n "${rust_path}" ]] || fail "could not read DEFAULT_HOSTOS_METRICS_PROXY_OUTPUT_PATH from ${CONFIG_LIB_RS}"

    local unit_path
    unit_path=$(sed -n 's|^ExecStart=/opt/ic/bin/metrics-proxy \(.*\)$|\1|p' "${OVERRIDE}")
    [[ -n "${unit_path}" ]] || fail "no metrics-proxy ExecStart found in ${OVERRIDE}"

    [[ "${unit_path}" == "${rust_path}" ]] \
        || fail "drop-in runs '${unit_path}' but the generator writes '${rust_path}'"
    pass "drop-in and generator agree on ${rust_path}"
}

# Without the empty ExecStart= reset, systemd rejects the unit: a non-oneshot
# service may carry only one ExecStart.
function test_execstart_is_reset() {
    grep -qx 'ExecStart=' "${OVERRIDE}" || fail "${OVERRIDE} does not reset ExecStart= before setting its own"
    pass "drop-in resets ExecStart= before overriding it"

    local base_count
    base_count=$(grep -c '^ExecStart=' "${BASE_UNIT}")
    [[ "${base_count}" -eq 1 ]] || fail "expected one ExecStart= in ${BASE_UNIT}, found ${base_count}"
    pass "base unit carries a single ExecStart="
}

# Ordering only; a Requires= here would strand metrics-proxy if generation failed.
function test_ordering_without_requires() {
    grep -qx "After=${GENERATOR_UNIT}" "${OVERRIDE}" || fail "${OVERRIDE} must order After=${GENERATOR_UNIT}"
    grep -qx "Wants=${GENERATOR_UNIT}" "${OVERRIDE}" || fail "${OVERRIDE} must pull in the generator with Wants="
    ! grep -q "^Requires=${GENERATOR_UNIT}" "${OVERRIDE}" \
        || fail "${OVERRIDE} uses Requires=, which cancels metrics-proxy if generation fails"
    pass "drop-in orders after the generator and pulls it in with Wants="
}

# The reward type comes off the config partition, so the mount has to be there.
function test_generator_requires_config_mount() {
    grep -qx 'RequiresMountsFor=/boot/config' "${GENERATOR}" \
        || fail "${GENERATOR} must declare RequiresMountsFor=/boot/config"
    pass "generator requires the config partition to be mounted"
}

# systemd's own parser, on the version HostOS ships. Its exit code is dominated
# by /opt/ic binaries being absent outside the image, so only other complaints
# count; the image itself is checked by component_file_references_test.
function test_units_parse() {
    if ! command -v systemd-analyze >/dev/null; then
        fail "systemd-analyze not found"
    fi

    local unit output
    for unit in "${GENERATOR}" "${BASE_UNIT}"; do
        output=$(systemd-analyze verify "${unit}" 2>&1 || true)
        output=$(grep -v 'is not executable: No such file or directory' <<<"${output}" || true)
        [[ -z "${output}" ]] || fail "systemd-analyze rejected ${unit}:\n${output}"
        pass "systemd-analyze accepts $(basename "${unit}")"
    done
}

echo
echo "Running HostOS metrics-proxy unit tests..."
test_config_path_agrees_with_generator
test_execstart_is_reset
test_ordering_without_requires
test_generator_requires_config_mount
test_units_parse
echo
echo "PASSED HostOS metrics-proxy unit tests"
echo
