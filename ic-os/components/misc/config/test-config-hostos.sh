#!/usr/bin/env bash

set -euo pipefail

CONFIG_HOSTOS_SCRIPT="${1:-./config-hostos.sh}"

source "${CONFIG_HOSTOS_SCRIPT}"

function test_get_guest_vm_suffix() {
    test_get_guest_vm_suffix_helper 1 1 ""
    test_get_guest_vm_suffix_helper 1 2 "1"
    test_get_guest_vm_suffix_helper 2 2 "2"
    test_get_guest_vm_suffix_helper 1 60 "1"
    test_get_guest_vm_suffix_helper 60 60 "60"
    test_get_guest_vm_suffix_helper 15 15 "15"
}

function test_get_guest_vm_suffix_helper() {
    local slot="$1"
    local count="$2"
    local expected="$3"

    local actual
    actual=$(get_guest_vm_suffix "${slot}" "${count}")

    if [[ "${actual}" == "${expected}" ]]; then
        echo "  PASS: slot ${slot} of ${count} -> '${expected}'"
    else
        echo "  FAIL: slot ${slot} of ${count} -> '${actual}', expected '${expected}'"
        exit 1
    fi
}

# The VM names a monitoring loop produces must match what guest_vm_runner
# derives from VmSlot. A single-VM node uses the unsuffixed name, and a
# multi-VM node starts at 1, so guestos0 must never appear.
function test_vm_names() {
    test_vm_names_helper 1 "guestos"
    test_vm_names_helper 2 "guestos1 guestos2"
    test_vm_names_helper 4 "guestos1 guestos2 guestos3 guestos4"
}

function test_vm_names_helper() {
    local count="$1"
    local expected="$2"

    local names=()
    for i in $(seq 1 "${count}"); do
        names+=("guestos$(get_guest_vm_suffix "${i}" "${count}")")
    done

    if [[ "${names[*]}" == "${expected}" ]]; then
        echo "  PASS: ${count} VM(s) -> ${expected}"
    else
        echo "  FAIL: ${count} VM(s) -> ${names[*]}, expected ${expected}"
        exit 1
    fi

    if [[ " ${names[*]} " == *" guestos0 "* ]]; then
        echo "  FAIL: ${count} VM(s) produced guestos0"
        exit 1
    fi
}

echo
echo "Running config-hostos.sh unit tests..."
test_get_guest_vm_suffix
test_vm_names
echo
echo "PASSED config-hostos unit tests"
echo
