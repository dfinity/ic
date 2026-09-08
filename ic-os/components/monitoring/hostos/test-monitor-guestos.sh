#!/usr/bin/env bash

set -euo pipefail

MONITOR_GUESTOS_SCRIPT="${1:-./monitor-guestos.sh}"
START_GUESTOS_SCRIPT="${2:-../../hostos/guestos/start-guestos.sh}"
GUESTOS_VM_COUNT_SCRIPT="${3:-../../misc/guestos-vm-count.sh}"

# Reward types to check. Deliberately no VM counts here: the counts are read
# out of start-guestos.sh so that this test cannot drift away from it.
REWARD_TYPES=(type1.1 type3.1 type4 type4.1 type4.2 type4.3 type4.4 type4.5)

# ------------------------------------------------------------------------------
# Mocks. Both scripts source their libraries from /opt/ic/bin and reach systemd
# and libvirt through systemctl and virsh, none of which exist here.
# ------------------------------------------------------------------------------
function source() {
    case "$1" in
        # Defines the counts and slots under test, so load the real one.
        /opt/ic/bin/guestos-vm-count.sh) builtin source "$GUESTOS_VM_COUNT_SCRIPT" ;;
        /opt/ic/bin/*) ;;
        *) builtin source "$@" ;;
    esac
}

# ------------------------------------------------------------------------------
# The slots start-guestos.sh boots for a node of reward type $1, one per line.
# Runs in a subshell because start-guestos.sh exits on the single-GuestOS path.
# ------------------------------------------------------------------------------
function booted_slots() (
    local reward_type="$1"

    function get_config_value() { echo "$reward_type"; }

    function systemctl() {
        local arg
        for arg in "$@"; do
            if [[ "$arg" == guestos@*.service ]]; then
                arg="${arg#guestos@}"
                echo "${arg%.service}"
            fi
        done
    }

    # Both scripts reject arguments, and a sourced script inherits the caller's.
    set --
    set +u
    builtin source "$START_GUESTOS_SCRIPT"
)

# ------------------------------------------------------------------------------
# The "<domain>=<state>" metrics monitor-guestos.sh writes for a node of reward
# type $1, given $2 as the defined and $3 as the running domains.
# ------------------------------------------------------------------------------
function observed_metrics() (
    local reward_type="$1" defined="$2" running="$3" observed=""

    function get_config_value() { echo "$reward_type"; }
    function write_log() { :; }

    function virsh() {
        case " $* " in
            *" --state-running "*) tr ' ' '\n' <<<"$running" ;;
            *) tr ' ' '\n' <<<"$defined" ;;
        esac
    }

    function write_metric_attr() {
        # Called as: write_metric_attr <name> {vm="<domain>"} <state> <help> <type>
        local domain="${2#*\"}"
        observed+=" ${domain%%\"*}=${3}"
    }

    # Both scripts reject arguments, and a sourced script inherits the caller's.
    set --
    set +u
    builtin source "$MONITOR_GUESTOS_SCRIPT"
    echo "${observed# }"
)

# ------------------------------------------------------------------------------
# The libvirt domain name for a VM slot. Mirrors VmSlot::to_suffix() in
# rs/ic_os/config/types/src/lib.rs: slot 0, the single GuestOS, has no suffix.
# ------------------------------------------------------------------------------
function domain_name() {
    if [ "$1" -eq 0 ]; then
        echo "guestos"
    else
        echo "guestos$1"
    fi
}

function fail() {
    echo "  FAIL: $1"
    echo "    expected: $2"
    echo "    actual:   $3"
    exit 1
}

# ------------------------------------------------------------------------------
# monitor-guestos.sh must poll exactly the VMs start-guestos.sh boots. Deriving
# the expectation from start-guestos.sh is what makes this catch a VM count that
# is changed in one script but not the other, as well as a slot numbering that
# does not line up with the units that are actually started.
# ------------------------------------------------------------------------------
echo "Running test: monitored VMs match booted VMs"
for reward_type in "${REWARD_TYPES[@]}"; do
    slots=($(booted_slots "$reward_type"))

    if [ "${#slots[@]}" -eq 0 ]; then
        fail "$reward_type boots no GuestOS at all" "at least one slot" "none"
    fi

    domains=()
    for slot in "${slots[@]}"; do
        domains+=("$(domain_name "$slot")")
    done

    # Every booted VM is defined and running, so each must report state 0.
    expected=""
    for domain in "${domains[@]}"; do
        expected+=" ${domain}=0"
    done

    actual="$(observed_metrics "$reward_type" "${domains[*]}" "${domains[*]}")"
    if [[ "$actual" != "${expected# }" ]]; then
        fail "$reward_type monitors the ${#slots[@]} VMs it boots" "${expected# }" "$actual"
    fi
    echo "  PASS: ${reward_type} boots and monitors ${#slots[@]} VM(s):" \
        "${domains[0]}..${domains[$((${#domains[@]} - 1))]}"
done

# ------------------------------------------------------------------------------
# The state monitor-guestos.sh reports per VM, which is its own logic rather
# than something start-guestos.sh has an opinion about.
# ------------------------------------------------------------------------------
echo "Running test: reported VM states"
for spec in \
    "type1.1|guestos|guestos|guestos=0" \
    "type1.1|guestos||guestos=2" \
    "type1.1|||guestos=1" \
    "type4.4|guestos1 guestos2|guestos1|guestos1=0 guestos2=2" \
    "type4.4|guestos1|guestos1|guestos1=0 guestos2=1"; do
    IFS='|' read -r reward_type defined running expected <<<"$spec"

    actual="$(observed_metrics "$reward_type" "$defined" "$running")"
    if [[ "$actual" != "$expected" ]]; then
        fail "$reward_type with [${defined:-none}] defined, [${running:-none}] running" \
            "$expected" "$actual"
    fi
    echo "  PASS: ${reward_type} with [${defined:-none}] defined, [${running:-none}] running"
done

echo "All monitor-guestos.sh tests passed"
