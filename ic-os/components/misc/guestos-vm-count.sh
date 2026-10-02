#!/bin/bash

# How many GuestOS a node runs, and in which slots. Requires config.sh.
#
# Counts must match split_resources_for_type_4() in
# rs/ic_os/os_tools/guest_vm_runner/src/guest_vm_config.rs, which splits the
# host's memory and vCPUs by the same numbers.

guestos_vm_count_for_reward_type() {
    case "${1}" in
        type4.1) echo 60 ;;
        type4.2) echo 15 ;;
        type4.3) echo 4 ;;
        type4.4) echo 2 ;;
        *) echo 1 ;;
    esac
}

guestos_vm_count() {
    guestos_vm_count_for_reward_type \
        "$(get_config_value '.icos_settings.node_reward_type')"
}

# Slots for $1 GuestOS, one per line. Mirrors VmSlot in
# rs/ic_os/config/types/src/lib.rs: one GuestOS uses slot 0, several use 1..count.
guestos_vm_slots_for_count() {
    if [ "${1}" -eq 1 ]; then
        echo 0
    else
        seq 1 "${1}"
    fi
}

guestos_vm_slots() {
    guestos_vm_slots_for_count "$(guestos_vm_count)"
}

# Name suffix for slot $1. Mirrors VmSlot::to_suffix(): slot 0 is unsuffixed.
guestos_vm_slot_suffix() {
    if [ "${1}" -eq 0 ]; then
        echo ""
    else
        echo "${1}"
    fi
}
