#!/usr/bin/env bash

###############################################################################
# Environment & Script Setup
###############################################################################

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/config.sh
source /opt/ic/bin/functions.sh

HARDWARE_GENERATION=

###############################################################################
# Hardware Requirements
###############################################################################

GEN1_CPU_MODEL="AMD EPYC 7302"
GEN1_CPU_CAPABILITIES=("svm" "sev")
GEN1_CPU_SOCKETS=2
GEN1_CPU_THREADS=64
# Gen1 Dell has 10 * 3.2TB drives, Gen1 SuperMicro has 5 * 6.4TB drives, Gen2 has 5 * 6.4TB drives = 32TB
MINIMUM_AGGREGATE_DISK_SIZE=32000000000000

# SEV-SNP was introduced with Milan (EPYC 7003), so that is generation minimum.
# Also support newer generations: 8000 (Siena) and 9000 (Genoa/Turin).
GEN2_CPU_MODEL="AMD EPYC (7..[3-9]|[89][0-9]+)"
GEN2_CPU_CAPABILITIES=("svm" "sev_snp")
GEN2_MINIMUM_CPU_SOCKETS=2
GEN2_MINIMUM_CPU_THREADS=64

# Memory requirement for all nodes: 510 GB (just under the 512 GB publicly-listed requirement)
MINIMUM_MEMORY_SIZE=547608330240

###############################################################################
# Helper Functions
###############################################################################

function get_cpu_info_json() {
    local cpu_json="$(lshw -quiet -class cpu -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch CPU information."
    echo "${cpu_json}"
}

###############################################################################
# Hardware Generation Inference
###############################################################################

function detect_hardware_generation() {
    echo "* Inferring hardware generation from node reward type..."

    local node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

    # All type0.* and type1.* are considered gen1, all type3.* are gen2, all type4.* are cloud engine nodes
    if [[ $node_reward_type =~ ^type(0|1)(\.[0-9]+)?$ ]]; then
        HARDWARE_GENERATION=1
    elif [[ $node_reward_type =~ ^type3(\.[0-9]+)?$ ]]; then
        HARDWARE_GENERATION=2
    elif [[ $node_reward_type =~ ^type4(\.[0-9]+)?$ ]]; then
        HARDWARE_GENERATION=3
    else
        log_and_halt_installation_on_error "1" "Unknown or unsupported node reward type '${node_reward_type}'."
    fi

    echo "* Hardware generation ${HARDWARE_GENERATION} detected"
}

###############################################################################
# CPU Verification
###############################################################################

function check_num_cpus() {
    local cpu_json="$1"
    local required_sockets="$2"

    local num_cpu_sockets=$(echo "${cpu_json}" | jq -r '.[] | select(has("disabled") | not) | .id' | wc -l)
    log_and_halt_installation_on_error "$?" "Unable to extract CPU sockets from CPU JSON."

    if [ "${num_cpu_sockets}" -lt "${required_sockets}" ]; then
        log_and_halt_installation_on_error "1" "Number of CPU sockets (${num_cpu_sockets}) does NOT meet system requirements (expected ${required_sockets})."
    fi
}

function verify_capability_for_all_sockets() {
    local cpu_json="$1"
    local capability_name="$2"

    for socket_id in $(echo "${cpu_json}" | jq -r '.[] | select(has("disabled") | not) | .id'); do
        local capability=$(echo "${cpu_json}" | jq -r \
            --arg socket "${socket_id}" \
            --arg capability "${capability_name}" \
            '.[] | select(.id==$socket) | .capabilities[$capability]')
        log_and_halt_installation_on_error "$?" "Failed to query CPU capabilities"

        echo -n "* Socket ${socket_id}: capability '${capability_name}' "
        if [[ ${capability} =~ .*true.* ]]; then
            echo "is present"
        else
            echo "is missing"
            return 1
        fi
    done

    return 0
}

function verify_model_for_all_sockets() {
    local cpu_json="$1"
    local required_model="$2"

    for socket_id in $(echo "${cpu_json}" | jq -r '.[] | select(has("disabled") | not) | .id'); do
        local model=$(echo "${cpu_json}" | jq -r --arg socket "${socket_id}" '.[] | select(.id==$socket) | .product')

        echo -n "* CPU model '${model}' "
        if [[ ${model} =~ .*${required_model}.* ]]; then
            echo "meets system requirements"
        else
            echo "does NOT meet system requirements"
            return 1
        fi
    done

    return 0
}

function verify_model_and_capabilities_for_all_sockets() {
    local cpu_json="$1"
    local required_model="$2"
    shift 2
    local required_capabilities=("$@")

    verify_model_for_all_sockets "${cpu_json}" "${required_model}"
    log_and_halt_installation_on_error "$?" "One or more CPU's model does NOT meet system requirements"

    for capability_name in "${required_capabilities[@]}"; do
        verify_capability_for_all_sockets "${cpu_json}" "${capability_name}"
        log_and_halt_installation_on_error "$?" "CPU capabilities do NOT meet system requirements"
    done
}

function verify_gen1_cpu() {
    local cpu_json="$(get_cpu_info_json)"

    check_num_cpus "${cpu_json}" "${GEN1_CPU_SOCKETS}"

    verify_model_and_capabilities_for_all_sockets \
        "${cpu_json}" \
        "${GEN1_CPU_MODEL}" \
        "${GEN1_CPU_CAPABILITIES[@]}"

    local num_threads=$(nproc)
    if [ "${num_threads}" -eq "${GEN1_CPU_THREADS}" ]; then
        echo "Number of threads (${num_threads}/${GEN1_CPU_THREADS}) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Number of threads (${num_threads}/${GEN1_CPU_THREADS}) does NOT meet system requirements."
    fi
}

function verify_gen2_cpu() {
    local cpu_json="$(get_cpu_info_json)"

    check_num_cpus "${cpu_json}" "${GEN2_MINIMUM_CPU_SOCKETS}"

    verify_model_and_capabilities_for_all_sockets \
        "${cpu_json}" \
        "${GEN2_CPU_MODEL}" \
        "${GEN2_CPU_CAPABILITIES[@]}"

    local num_threads=$(nproc)
    if [ "${num_threads}" -lt "${GEN2_MINIMUM_CPU_THREADS}" ]; then
        log_and_halt_installation_on_error "1" "Number of threads (${num_threads}) does NOT meet system requirements (${GEN2_MINIMUM_CPU_THREADS})."
    fi
}

function verify_generic_cpu() {
    local cpu_json="$(get_cpu_info_json)"

    # Check if AMD or Intel virtualization technology is present & enabled in BIOS/UEFI
    verify_capability_for_all_sockets "${cpu_json}" "svm" || verify_capability_for_all_sockets "${cpu_json}" "vmx"
    log_and_halt_installation_on_error "$?" "CPU does not have virtualization extensions enabled"

    echo "CPU capabilities meet system requirements"
}

function verify_cpu() {
    echo "* Verifying hardware generation ${HARDWARE_GENERATION} CPU..."

    if [[ "${HARDWARE_GENERATION}" == "1" ]]; then
        verify_gen1_cpu
    elif [[ "${HARDWARE_GENERATION}" == "2" ]]; then
        verify_gen2_cpu
    else
        verify_generic_cpu
    fi
}

###############################################################################
# Memory Verification
###############################################################################

function verify_memory() {
    echo "* Verifying system memory..."

    local memory="$(lshw -quiet -class memory -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch memory information."

    local size=$(echo "${memory}" | jq -r '.[] | select(.id=="memory") | .size')
    log_and_halt_installation_on_error "${?}" "Unable to extract memory size."

    if [ "${size}" -ge "${MINIMUM_MEMORY_SIZE}" ]; then
        echo "Memory size (${size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Memory size (${size} bytes/${MINIMUM_MEMORY_SIZE}) does NOT meet system requirements."
    fi
}

###############################################################################
# Disk Verification
###############################################################################

function verify_disks() {
    echo "* Verifying disks..."
    local aggregate_size=0
    local large_drives=($(get_large_drives))

    for drive in "${large_drives[@]}"; do
        echo "* Verifying disk ${drive}"

        test -b "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        local disk="$(lsblk --bytes --json /dev/${drive})"
        log_and_halt_installation_on_error "${?}" "Unable to fetch disk information."

        local disk_size=$(echo "${disk}" | jq -r \
            --arg logicalname "${drive}" \
            '.[][] | select(.name==$logicalname) | .size')
        log_and_halt_installation_on_error "${?}" "Unable to extract disk size."

        echo "Disk size: ${disk_size} bytes"
        aggregate_size=$((aggregate_size + disk_size))
    done

    if [ "${aggregate_size}" -ge "${MINIMUM_AGGREGATE_DISK_SIZE}" ]; then
        echo "Aggregate Disk size (${aggregate_size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Aggregate Disk size (${aggregate_size} bytes/${MINIMUM_AGGREGATE_DISK_SIZE}) does NOT meet system requirements."
    fi
}

###############################################################################
# Drive Health Verification
###############################################################################

function verify_drive_health() {
    echo "* Verifying drive health..."

    local drives=($(get_large_drives))
    local warning_triggered=0

    for drive in "${drives[@]}"; do
        echo "* Checking drive /dev/${drive} health..."
        local smartctl_output
        if ! smartctl_output=$(smartctl -H /dev/${drive} 2>&1); then
            echo -e "\033[1;31mWARNING: Failed to run smartctl on /dev/${drive}.\033[0m"
            warning_triggered=1
        elif ! echo "${smartctl_output}" | grep -qi "PASSED"; then
            echo -e "\033[1;31mWARNING: Drive /dev/${drive} did not pass the SMART health check.\033[0m"
            warning_triggered=1
        else
            echo "Drive /dev/${drive} health is OK."
        fi
    done

    if [ "${warning_triggered}" -eq 1 ]; then
        echo "Pausing for 5 minutes before continuing installation..."
        sleep 300
    fi
}

###############################################################################
# Deployment Path Verification
###############################################################################

function verify_deployment_path() {
    echo "* Verifying deployment path..."

    if [[ "${HARDWARE_GENERATION}" == "2" ]] && [[ ! -f "/config/node_operator_private_key.pem" ]]; then
        echo -e "\n\n\n\n\n\n"
        echo -e "\033[1;31mWARNING: Gen2 hardware detected but no Node Operator Private Key found.\033[0m"
        echo -e "\033[1;31mGen2 hardware should be deployed using the Gen2 Node Deployment method.\033[0m"
        echo -e "\033[1;31m\nIf you already completed your *Node Provider onboarding* using the legacy procedure (with an HSM), \033[0m"
        echo -e "\033[1;31myou may continue your HSM node deployment (just wait 5 minutes for the installation to resume).\033[0m"
        echo -e "\n\n\n"
        echo "Pausing for 5 minutes before continuing installation..."
        sleep 300
    fi
}

function verify_sev_snp() {
    local enabled=$(get_config_value '.icos_settings.enable_trusted_execution_environment')
    if [[ "${enabled}" == "true" ]]; then
        if [[ "${HARDWARE_GENERATION}" != "2" ]]; then
            log_and_halt_installation_on_error "1" "Trusted execution is enabled but hardware generation is not Gen2."
        else
            echo "Trusted execution is enabled and Gen2 hardware detected."
        fi
    else
        echo "Trusted execution is disabled. Skipping verification."
    fi
}

###############################################################################
# Main
###############################################################################

main() {
    log_start "$(basename $0)"
    if check_cmdline_var ic.setupos.run_checks; then
        detect_hardware_generation
        verify_cpu

        if [[ "${HARDWARE_GENERATION}" == "3" ]]; then
            echo "* Cloud Engine node detected, skipping most checks"
        else
            verify_memory
            verify_disks
            verify_drive_health
            verify_deployment_path
            verify_sev_snp
        fi
    else
        echo "* Hardware checks skipped by request via kernel command line"
    fi
    log_end "$(basename $0)"
}

main
