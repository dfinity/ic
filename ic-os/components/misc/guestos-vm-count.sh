#!/bin/bash

# How many GuestOS virtual machines a node runs, and in which slots.
#
# type4 ("cloud engine") nodes run several GuestOS on one host; every other
# node type runs one. The counts here must stay in line with
# split_resources_for_type_4() in
# rs/ic_os/os_tools/guest_vm_runner/src/guest_vm_config.rs, which divides the
# host's memory and vCPUs by the same numbers.
#
# Sourced by install-hostos.sh (creates the volumes), start-guestos.sh (boots
# the units), monitor-guestos.sh and export-guestos-serial-logs.sh. Requires
# get_config_value from config.sh.

# Number of GuestOS a node of reward type $1 runs.
guestos_vm_count_for_reward_type() {
    case "${1}" in
        type4.1) echo 60 ;;
        type4.2) echo 15 ;;
        type4.3) echo 4 ;;
        type4.4) echo 2 ;;
        *) echo 1 ;;
    esac
}

# Number of GuestOS this node runs, per its config.
guestos_vm_count() {
    guestos_vm_count_for_reward_type \
        "$(get_config_value '.icos_settings.node_reward_type')"
}

# The slots a node running $1 GuestOS uses, one per line. Mirrors VmSlot in
# rs/ic_os/config/types/src/lib.rs: a single GuestOS occupies slot 0, several
# occupy slots 1..count.
guestos_vm_slots_for_count() {
    if [ "${1}" -eq 1 ]; then
        echo 0
    else
        seq 1 "${1}"
    fi
}

# The slots this node uses, one per line.
guestos_vm_slots() {
    guestos_vm_slots_for_count "$(guestos_vm_count)"
}

# The name suffix for slot $1. Mirrors VmSlot::to_suffix(): slot 0, the single
# GuestOS, is unsuffixed, so it keeps the plain `guestos` name.
guestos_vm_slot_suffix() {
    if [ "${1}" -eq 0 ]; then
        echo ""
    else
        echo "${1}"
    fi
}
