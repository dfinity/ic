#!/usr/bin/env bash

set -o nounset
set -o pipefail

source /opt/ic/bin/config.sh
source /opt/ic/bin/functions.sh

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

GENERATION=

MINIMUM_CPU_SOCKETS=2

GEN1_CPU_MODEL="AMD EPYC 7302"
GEN1_CPU_CAPABILITIES=("sev")
GEN1_CPU_SOCKETS=2
GEN1_CPU_THREADS=64

GEN2_CPU_MODEL="AMD EPYC 7..3"
GEN2_CPU_CAPABILITIES=("sev_snp")
GEN2_MINIMUM_CPU_THREADS=64

# 510 GiB (Gibibyte)
MINIMUM_MEMORY_SIZE=547608330240

# Gen2 has 5 * 6.4 TB drives = 32TB
GEN2_MINIMUM_DISK_SIZE=6400000000000
GEN2_MINIMUM_AGGREGATE_DISK_SIZE=32000000000000

# Dell 10 3.2TB and SuperMicro has 5 7.4 TB drives = 32TB
GEN1_MINIMUM_DISK_SIZE=3200000000000
GEN1_MINIMUM_AGGREGATE_DISK_SIZE=32000000000000

function check_generation() {
    echo "* Checking Generation..."

    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch CPU information."

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        if [[ ${i} =~ .*:.* ]]; then
            unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        else
            unit=${i}
        fi
        echo "* Checking CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${GEN1_CPU_MODEL}.* ]]; then
            if [[ ${GENERATION} =~ ^(|1)$ ]]; then
                GENERATION=1
            else
                log_and_halt_installation_on_error "1" "  CPU Socket Generations inconsistent."
            fi
        elif [[ ${model} =~ .*${GEN2_CPU_MODEL}.* ]]; then
            if [[ ${GENERATION} =~ ^(|2)$ ]]; then
                GENERATION=2
            else
                log_and_halt_installation_on_error "1" "  CPU Socket Generations inconsistent."
            fi
        else
            log_and_halt_installation_on_error "2" "  CPU Model does NOT meet system requirements."
        fi
    done
    echo "* Generation" ${GENERATION} "detected"
}

function check_num_cpus() {
    local num_cpu_sockets=$(lscpu | grep "Socket(s)" | awk '{print $2}')
    if [ ${num_cpu_sockets} -ne ${MINIMUM_CPU_SOCKETS} ]; then
        log_and_halt_installation_on_error "1" "Number of CPU's (${num_cpu_sockets}) does NOT meet system requirements (${MINIMUM_CPU_SOCKETS})."
    fi
}

function verify_gen1_cpu() {
    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch CPU information."

    local sockets=$(echo "${cpu}" | jq -r '.[].id' | wc -l)
    log_and_halt_installation_on_error "${?}" "Unable to extract CPU sockets."

    if [ ${sockets} -eq ${GEN1_CPU_SOCKETS} ]; then
        echo "  Number of sockets (${sockets}/${GEN1_CPU_SOCKETS}) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "  Number of sockets (${sockets}/${GEN1_CPU_SOCKETS}) does NOT meet system requirements."
    fi

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        echo "* Verifying CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${GEN1_CPU_MODEL}.* ]]; then
            echo "  Model meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for c in "${GEN1_CPU_CAPABILITIES[@]}"; do
            local capability=$(echo "${cpu}" | jq -r --arg socket "${i}" --arg capability "${c}" '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_halt_installation_on_error "$?" "Capability '${c}' does NOT meet system requirements.."

            if [[ ${capability} =~ .*true.* ]]; then
                echo "  Capability '${c}' meets system requirements."
            else
                log_and_halt_installation_on_error "$?" "Capability '${c}' does NOT meet system requirements.."
            fi
        done

        local num_threads=$(nproc)
        if [ ${num_threads} -eq ${GEN1_CPU_THREADS} ]; then
            echo "  Number of threads (${num_threads}/${GEN1_CPU_THREADS}) meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Number of threads (${num_threads}/${GEN1_CPU_THREADS}) does NOT meet system requirements."
        fi
    done
}

function verify_gen2_cpu() {
    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch CPU information."

    check_num_cpus

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        echo "* Verifying CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${GEN2_CPU_MODEL}.* ]]; then
            echo "  Model meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for c in "${GEN2_CPU_CAPABILITIES[@]}"; do
            local capability=$(echo "${cpu}" | jq -r --arg socket "${i}" --arg capability "${c}" '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_halt_installation_on_error "$?" "Capability '${c}' does NOT meet system requirements.."

            if [[ ${capability} =~ .*true.* ]]; then
                echo "  Capability '${c}' meets system requirements."
            else
                log_and_halt_installation_on_error "$?" "Capability '${c}' does NOT meet system requirements.."
            fi
        done
    done

    local num_threads=$(nproc)
    if [ ${num_threads} -lt ${GEN2_MINIMUM_CPU_THREADS} ]; then
        log_and_halt_installation_on_error "1" "Number of threads (${num_threads}) does NOT meet system requirements (${GEN2_MINIMUM_CPU_THREADS})"
    fi
}

function verify_cpu() {
    echo "* Verifying Generation" ${GENERATION} "CPU..."
    if [[ ${GENERATION} == 1 ]]; then
        verify_gen1_cpu
    else
        verify_gen2_cpu
    fi
}

function verify_memory() {
    echo "* Verifying system memory..."

    local memory="$(lshw -quiet -class memory -json)"
    log_and_halt_installation_on_error "${?}" "Unable to fetch memory information."

    local size=$(echo ${memory} | jq -r '.[] | select(.id=="memory") | .size')
    log_and_halt_installation_on_error "${?}" "Unable to extract memory size."

    if [ "${size}" -gt "${MINIMUM_MEMORY_SIZE}" ]; then
        echo "  Memory size (${size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Memory size (${size} bytes/${MINIMUM_MEMORY_SIZE}) does NOT meet system requirements."
    fi
}

function verify_gen1_disks() {
    aggregate_size=0
    large_drives=($(get_large_drives))
    for drive in $(echo "${large_drives[@]}"); do
        test -b "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        local disk="$(lsblk --bytes --json /dev/${drive})"
        log_and_halt_installation_on_error "${?}" "Unable to fetch disk information."

        local disk_size=$(echo ${disk} | jq -r --arg logicalname "${drive}" '.[][] | select(.name==$logicalname) | .size')
        log_and_halt_installation_on_error "${?}" "Unable to extract disk size."

        if [ "${disk_size}" -gt "${GEN1_MINIMUM_DISK_SIZE}" ]; then
            echo "  Disk size (${disk_size} bytes) meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Disk size (${disk_size} bytes/${GEN1_MINIMUM_DISK_SIZE}) does NOT meet system requirements."
        fi
        aggregate_size=$((aggregate_size + disk_size))
    done
    if [ "${aggregate_size}" -gt "${GEN1_MINIMUM_AGGREGATE_DISK_SIZE}" ]; then
        echo "  Aggregate Disk size (${aggregate_size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Aggregate Disk size (${aggregate_size} bytes/${GEN1_MINIMUM_AGGREGATE_DISK_SIZE}) does NOT meet system requirements."
    fi
}

function verify_gen2_disks() {
    aggregate_size=0
    large_drives=($(get_large_drives))
    for drive in $(echo "${large_drives[@]}"); do

        echo "* Verifying disk ${drive}"

        test -b "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        local disk="$(lsblk --bytes --json /dev/${drive})"
        log_and_halt_installation_on_error "${?}" "Unable to fetch disk information."

        local disk_size=$(echo ${disk} | jq -r --arg logicalname "${drive}" '.[][] | select(.name==$logicalname) | .size')
        log_and_halt_installation_on_error "${?}" "Unable to extract disk size."

        if [ "${disk_size}" -gt "${GEN2_MINIMUM_DISK_SIZE}" ]; then
            echo "  Disk size (${disk_size} bytes) meets system requirements."
        else
            log_and_halt_installation_on_error "1" "Disk size (${disk_size} bytes/${GEN2_MINIMUM_DISK_SIZE}) does NOT meet system requirements."
        fi
        aggregate_size=$((aggregate_size + disk_size))
    done
    if [ "${aggregate_size}" -gt "${GEN2_MINIMUM_AGGREGATE_DISK_SIZE}" ]; then
        echo "  Aggregate Disk size (${aggregate_size} bytes) meets system requirements."
    else
        log_and_halt_installation_on_error "1" "Aggregate Disk size (${aggregate_size} bytes/${GEN2_MINIMUM_AGGREGATE_DISK_SIZE}) does NOT meet system requirements."
    fi
}

function verify_disks() {
    echo "* Verifying disks..."
    if [[ ${GENERATION} == 1 ]]; then
        verify_gen1_disks
    else
        verify_gen2_disks
    fi
}

function verify_deployment_path() {
    echo "* Verifying deployment path..."

    local node_operator_key_path=$(get_config_value '.icos_settings.node_operator_private_key_path')

    if [[ ${GENERATION} == 2 ]] && [[ ! -f "${node_operator_key_path}" ]]; then
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

# Establish run order
main() {
    log_start "$(basename $0)"
    check_generation
    verify_cpu
    verify_memory
    verify_disks
    verify_deployment_path
    log_end "$(basename $0)"
}

main
