#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"
CONFIG="${CONFIG:=/config/tmp/config.ini}"

GENERATION=

GEN1_CPU_MODEL="AMD EPYC 7302"
GEN1_CPU_CAPABILITIES=("sev")
GEN1_CPU_CORES=16
GEN1_CPU_SOCKETS=2
GEN1_CPU_THREADS=32

GEN2_CPU_MODEL="AMD EPYC 7..3"
GEN2_CPU_CAPABILITIES=("sev_snp")
GEN2_MINIMUM_CPU_CORES=32
GEN2_MINIMUM_CPU_THREADS=64

# 510 GiB (Gibibyte)
MINIMUM_MEMORY_SIZE=547608330240

SYSTEM_DISK_NAME="nvme0n1"
# 2900 GiB (Gibibyte)
MINIMUM_SYSTEM_DISK_SIZE=3113851289600

GEN2_DATA_DISK_NAMES=("nvme0n1" "nvme1n1" "nvme2n1" "nvme3n1" "nvme4n1")
# 6.4TB
GEN2_MINIMUM_DATA_DISK_SIZE=6400000000000

# Dell 10 3.2TB and SuperMicro has 5 7.4 TB drives = 32TB
GEN1_MINIMUM_DATA_DISK_SIZE=3200000000000
GEN1_MINIMUM_AGGREGATE_DATA_DISK_SIZE=32000000000000

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "development_mode") development_mode="${value}" ;;
        esac
    done <"${CONFIG}"
}

function check_generation() {
    echo "* Checking Generation..."

    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_reboot_on_error "${?}" "Unable to fetch CPU information."

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
                log_and_reboot_on_error "1" "  CPU Socket Generations inconsistent."
            fi
        elif [[ ${model} =~ .*${GEN2_CPU_MODEL}.* ]]; then
            if [[ ${GENERATION} =~ ^(|2)$ ]]; then
                GENERATION=2
            else
                log_and_reboot_on_error "1" "  CPU Socket Generations inconsistent."
            fi
        else
            log_and_reboot_on_error "2" "  CPU Model does NOT meet system requirements."
        fi
    done
    echo "* Generation" ${GENERATION} "detected"
}

function verify_gen1_cpu() {
    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_reboot_on_error "${?}" "Unable to fetch CPU information."

    local sockets=$(echo "${cpu}" | jq -r '.[].id' | wc -l)
    log_and_reboot_on_error "${?}" "Unable to extract CPU sockets."

    if [ ${sockets} -eq ${GEN1_CPU_SOCKETS} ]; then
        echo "  Number of sockets (${sockets}/${GEN1_CPU_SOCKETS}) meets system requirements."
    else
        log_and_reboot_on_error "1" "  Number of sockets (${sockets}/${GEN1_CPU_SOCKETS}) does NOT meet system requirements."
    fi

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        echo "* Verifying CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${GEN1_CPU_MODEL}.* ]]; then
            echo "  Model meets system requirements."
        else
            log_and_reboot_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for c in ${GEN1_CPU_CAPABILITIES[@]}; do
            local capability=$(echo "${cpu}" | jq -r --arg socket "${i}" --arg capability "${c}" '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."

            if [[ ${capability} =~ .*true.* ]]; then
                echo "  Capability '${c}' meets system requirements."
            else
                log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."
            fi
        done

        local cores=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.cores')
        if [ ${cores} -eq ${GEN1_CPU_CORES} ]; then
            echo "  Number of cores (${cores}/${GEN1_CPU_CORES}) meets system requirements."
        else
            log_and_reboot_on_error "1" "Number of cores (${cores}/${GEN1_CPU_CORES}) does NOT meet system requirements."
        fi

        local threads=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.threads')
        if [ ${threads} -eq ${GEN1_CPU_THREADS} ]; then
            echo "  Number of threads (${threads}/${GEN1_CPU_THREADS}) meets system requirements."
        else
            log_and_reboot_on_error "1" "Number of threads (${threads}/${GEN1_CPU_THREADS}) does NOT meet system requirements."
        fi
    done
}

function verify_gen2_cpu() {
    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_reboot_on_error "${?}" "Unable to fetch CPU information."

    local cores=0
    local threads=0

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        echo "* Verifying CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${GEN2_CPU_MODEL}.* ]]; then
            echo "  Model meets system requirements."
        else
            log_and_reboot_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for c in ${GEN2_CPU_CAPABILITIES[@]}; do
            local capability=$(echo "${cpu}" | jq -r --arg socket "${i}" --arg capability "${c}" '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."

            if [[ ${capability} =~ .*true.* ]]; then
                echo "  Capability '${c}' meets system requirements."
            else
                log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."
            fi
        done

        local socket_cores=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.cores')
        cores=$((cores + socket_cores))

        local socket_threads=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.threads')
        threads=$((threads + socket_threads))
    done

    if [ ${cores} -ge ${GEN2_MINIMUM_CPU_CORES} ]; then
        echo "  Number of cores (${cores}/${GEN2_MINIMUM_CPU_CORES}) meets system requirements."
    else
        log_and_reboot_on_error "1" "Number of cores (${cores}/${GEN2_MINIMUM_CPU_CORES}) does NOT meet system requirements."
    fi
    if [ ${threads} -ge ${GEN2_MINIMUM_CPU_THREADS} ]; then
        echo "  Number of threads (${threads}/${GEN2_MINIMUM_CPU_THREADS}) meets system requirements."
    else
        log_and_reboot_on_error "1" "Number of threads (${threads}/${GEN2_MINIMUM_CPU_THREADS}) does NOT meet system requirements."
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
    log_and_reboot_on_error "${?}" "Unable to fetch memory information."

    local size=$(echo ${memory} | jq -r '.[] | select(.id=="memory") | .size')
    log_and_reboot_on_error "${?}" "Unable to extract memory size."

    if [ "${size}" -gt "${MINIMUM_MEMORY_SIZE}" ]; then
        echo "  Memory size (${size} bytes) meets system requirements."
    else
        log_and_reboot_on_error "1" "Memory size (${size} bytes/${MINIMUM_MEMORY_SIZE}) does NOT meet system requirements."
    fi
}

function verify_system_disk() {
    echo "* Verifying system disk..."

    test -b "/dev/${SYSTEM_DISK_NAME}"
    log_and_reboot_on_error "${?}" "Drive '/dev/${SYSTEM_DISK_NAME}' not found. Are all drives correctly installed?"

    local disk="$(lsblk --bytes --json /dev/${SYSTEM_DISK_NAME})"
    log_and_reboot_on_error "${?}" "Unable to fetch disk information."

    local size=$(echo ${disk} | jq -r --arg logicalname "${SYSTEM_DISK_NAME}" '.[][] | select(.name==$logicalname) | .size')
    log_and_reboot_on_error "${?}" "Unable to extract disk size."

    if [ "${size}" -gt "${MINIMUM_SYSTEM_DISK_SIZE}" ]; then
        echo "  Disk size (${size} bytes) meets system requirements."
    else
        log_and_reboot_on_error "1" "Disk size (${size} bytes/${MINIMUM_SYSTEM_DISK_SIZE}) does NOT meet system requirements."
    fi
}

function verify_gen1_data_disks() {
    size=0
    large_drives=($(lsblk -nld -o NAME,SIZE | grep 'T$' | grep -o '^\S*'))
    for drive in $(echo ${large_drives[@]}); do
        test -b "/dev/${drive}"
        log_and_reboot_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        local disk="$(lsblk --bytes --json /dev/${drive})"
        log_and_reboot_on_error "${?}" "Unable to fetch disk information."

        local disk_size=$(echo ${disk} | jq -r --arg logicalname "${drive}" '.[][] | select(.name==$logicalname) | .size')
        log_and_reboot_on_error "${?}" "Unable to extract disk size."

        if [ "${disk_size}" -gt "${GEN1_MINIMUM_DATA_DISK_SIZE}" ]; then
            echo "  Disk size (${disk_size} bytes) meets system requirements."
        else
            log_and_reboot_on_error "1" "Disk size (${disk_size} bytes/${GEN1_MINIMUM_DATA_DISK_SIZE}) does NOT meet system requirements."
        fi
        size=$((size + disk_size))
    done
    if [ "${size}" -gt "${GEN1_MINIMUM_AGGREGATE_DATA_DISK_SIZE}" ]; then
        echo "  Aggregate Data Disk size (${size} bytes) meets system requirements."
    else
        log_and_reboot_on_error "1" "Aggregate Data Disk size (${size} bytes/${GEN1_MINIMUM_AGGREGATE_DATA_DISK_SIZE}) does NOT meet system requirements."
    fi
}

function verify_gen2_data_disks() {
    for i in ${GEN2_DATA_DISK_NAMES[@]}; do

        echo "* Verifying data disk ${i}"

        test -b "/dev/${i}"
        log_and_reboot_on_error "${?}" "Drive '/dev/${i}' not found. Are all drives correctly installed?"

        local disk="$(lsblk --bytes --json /dev/${i})"
        log_and_reboot_on_error "${?}" "Unable to fetch disk information."

        local size=$(echo ${disk} | jq -r --arg logicalname "${i}" '.[][] | select(.name==$logicalname) | .size')
        log_and_reboot_on_error "${?}" "Unable to extract disk size."

        if [ "${size}" -gt "${GEN2_MINIMUM_DATA_DISK_SIZE}" ]; then
            echo "  Disk size (${size} bytes) meets system requirements."
        else
            log_and_reboot_on_error "1" "Disk size (${size} bytes/${GEN2_MINIMUM_DATA_DISK_SIZE}) does NOT meet system requirements."
        fi
    done
    # The aggregate size is a function of the fixed (5) count and the GEN2_MINIMUM_DATA_DISK_SIZE so we
    # do not need to check it explicitly.
}

function verify_data_disks() {
    echo "* Verifying data disks..."
    if [[ ${GENERATION} == 1 ]]; then
        verify_gen1_data_disks
    else
        verify_gen2_data_disks
    fi
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    read_variables
    if [ "${development_mode:-}" != "on" ]; then
        check_generation
        verify_cpu
        verify_memory
        verify_system_disk
        verify_data_disks
    else
        echo "* DEVELOPMENT MODE: hardware NOT verified"
    fi
    log_end "$(basename $0)"
}

main
