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

# Support deploying Gen2 hardware with node_reward_type=type0, which checks Gen1 hardware requirements.
GEN1_CPU_MODEL="AMD EPYC (7302|7..3)"
GEN1_CPU_CAPABILITIES=("sev")
GEN1_CPU_SOCKETS=2
GEN1_CPU_THREADS=64
# Gen1 Dell has 10 * 3.2TB drives and Gen1 SuperMicro has 5 * 6.4 TB drives = 32TB
GEN1_MINIMUM_DISK_SIZE=3200000000000
GEN1_MINIMUM_AGGREGATE_DISK_SIZE=32000000000000

GEN2_CPU_MODEL="AMD EPYC 7..3"
GEN2_CPU_CAPABILITIES=("sev_snp")
GEN2_MINIMUM_CPU_SOCKETS=2
GEN2_MINIMUM_CPU_THREADS=64
# Gen2 has 5 * 6.4 TB drives = 32TB
GEN2_MINIMUM_DISK_SIZE=6400000000000
GEN2_MINIMUM_AGGREGATE_DISK_SIZE=32000000000000

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

    # All type0.* and type1.* are considered gen1, all type3.* are gen2
    if [[ $node_reward_type =~ ^type(0|1)(\.[0-9]+)?$ ]]; then
        HARDWARE_GENERATION=1
    elif [[ $node_reward_type =~ ^type3(\.[0-9]+)?$ ]]; then
        HARDWARE_GENERATION=2
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

    local num_cpu_sockets=$(echo "${cpu_json}" | jq -r '.[].id' | wc -l)
    log_and_halt_installation_on_error "$?" "Unable to extract CPU sockets from CPU JSON."

    if [ "${num_cpu_sockets}" -lt "${required_sockets}" ]; then
        log_and_halt_installation_on_error "1" "Number of CPU sockets (${num_cpu_sockets}) does NOT meet system requirements (expected ${required_sockets})."
    fi
}

function verify_model_and_capabilities_for_all_sockets() {
    local cpu_json="$1"
    local required_model="$2"
    shift 2
    local required_capabilities=("$@")

    for socket_id in $(echo "${cpu_json}" | jq -r '.[].id'); do
        local unit=$(echo "${socket_id}" | awk -F ':' '{ print $2 }')

        echo "* Verifying CPU socket ${unit}..."
        local model=$(echo "${cpu_json}" | jq -r --arg socket "${socket_id}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${required_model}.* ]]; then
            echo "Model meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for capability_name in "${required_capabilities[@]}"; do
            local capability=$(echo "${cpu_json}" | jq -r \
                --arg socket "${socket_id}" \
                --arg capability "${capability_name}" \
                '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_halt_installation_on_error "$?" "Failed to query CPU capabilities"

            if [[ ${capability} =~ .*true.* ]]; then
                echo "Capability '${capability_name}' meets system requirements."
            else
                log_and_halt_installation_on_error "$?" "Capability '${capability_name}' does NOT meet system requirements.."
            fi
        done
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
    if [ "${num_threads}" -ge "${GEN1_CPU_THREADS}" ]; then
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

function verify_cpu() {
    echo "* Verifying hardware generation ${HARDWARE_GENERATION} CPU..."

    if [[ "${HARDWARE_GENERATION}" == "1" ]]; then
        verify_gen1_cpu
    else
        verify_gen2_cpu
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

function verify_disks_helper() {
    local min_disk_size="${1}"
    local min_aggregate_disk_size="${2}"
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

        if [ "${disk_size}" -ge "${min_disk_size}" ]; then
            echo "Disk size (${disk_size} bytes) meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Disk size (${disk_size} bytes/${min_disk_size}) does NOT meet system requirements."
        fi

        aggregate_size=$((aggregate_size + disk_size))
    done

    if [ "${aggregate_size}" -ge "${min_aggregate_disk_size}" ]; then
        echo "Aggregate Disk size (${aggregate_size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Aggregate Disk size (${aggregate_size} bytes/${min_aggregate_disk_size}) does NOT meet system requirements."
    fi
}

function verify_disks() {
    echo "* Verifying disks..."
    if [[ "${HARDWARE_GENERATION}" == "1" ]]; then
        verify_disks_helper "${GEN1_MINIMUM_DISK_SIZE}" "${GEN1_MINIMUM_AGGREGATE_DISK_SIZE}"
    else
        verify_disks_helper "${GEN2_MINIMUM_DISK_SIZE}" "${GEN2_MINIMUM_AGGREGATE_DISK_SIZE}"
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
    local enabled=$(get_config_value '.hostos_settings.enable_trusted_execution_environment')
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
        verify_memory
        verify_disks
        verify_drive_health
        verify_deployment_path
        verify_sev_snp
    else
        echo "* Hardware checks skipped by request via kernel command line"
    fi
    log_end "$(basename $0)"
}

main
