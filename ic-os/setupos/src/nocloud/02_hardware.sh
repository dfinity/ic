#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CPU_CAPABILITIES=("sev")
CPU_CORES=16
CPU_SOCKETS=2
CPU_THREADS=32
CPU_MODEL="AMD EPYC 7302"

# 510 GiB (Gibibyte)
MEMORY_SIZE=547608330240

DISK_NAME="nvme0n1"
# 2900 GiB (Gibibyte)
DISK_SIZE=3113851289600

function verify_cpu() {
    echo "* Verifying CPU..."

    local cpu="$(lshw -quiet -class cpu -json)"
    log_and_reboot_on_error "${?}" "Unable to fetch CPU information."

    local sockets=$(echo "${cpu}" | jq -r '.[].id' | wc -l)
    log_and_reboot_on_error "${?}" "Unable to extract CPU sockets."

    if [ ${sockets} -eq ${CPU_SOCKETS} ]; then
        echo "Number of sockets (${sockets}/${CPU_SOCKETS}) meets system requirements."
    else
        log_and_reboot_on_error "1" "Number of sockets (${sockets}/${CPU_SOCKETS}) does NOT meet system requirements."
    fi

    for i in $(echo "${cpu}" | jq -r '.[].id'); do
        unit=$(echo ${i} | awk -F ':' '{ print $2 }')
        echo "* Verifying CPU socket ${unit}..."

        local model=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .product')
        if [[ ${model} =~ .*${CPU_MODEL}.* ]]; then
            echo "Model meets system requirements."
        else
            log_and_reboot_on_error "1" "Model does NOT meet system requirements.."
        fi

        echo "* Verifying CPU capabilities..."
        for c in ${CPU_CAPABILITIES[@]}; do
            local capability=$(echo "${cpu}" | jq -r --arg socket "${i}" --arg capability "${c}" '.[] | select(.id==$socket) | .capabilities[$capability]')
            log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."

            if [[ ${capability} =~ .*true.* ]]; then
                echo "Capability '${c}' meets system requirements."
            else
                log_and_reboot_on_error "$?" "Capability '${c}' does NOT meet system requirements.."
            fi
        done

        local cores=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.cores')
        if [ ${cores} -eq ${CPU_CORES} ]; then
            echo "Number of cores (${cores}/${CPU_CORES}) meets system requirements."
        else
            log_and_reboot_on_error "1" "Number of cores (${cores}/${CPU_CORES}) does NOT meet system requirements."
        fi

        local threads=$(echo "${cpu}" | jq -r --arg socket "${i}" '.[] | select(.id==$socket) | .configuration.threads')
        if [ ${threads} -eq ${CPU_THREADS} ]; then
            echo "Number of threads (${threads}/${CPU_THREADS}) meets system requirements."
        else
            log_and_reboot_on_error "1" "Number of threads (${threads}/${CPU_THREADS}) does NOT meet system requirements."
        fi
    done
}

function verify_memory() {
    echo "* Verifying system memory..."

    local memory="$(lshw -quiet -class memory -json)"
    log_and_reboot_on_error "${?}" "Unable to fetch memory information."

    local size=$(echo ${memory} | jq -r '.[] | select(.id=="memory") | .size')
    log_and_reboot_on_error "${?}" "Unable to extract memory size."

    if [ "${size}" -gt "${MEMORY_SIZE}" ]; then
        echo "Memory size (${size} bytes) meets system requirements."
    else
        log_and_reboot_on_error "1" "Memory size (${size} bytes) does NOT meet system requirements."
    fi
}

function verify_disk() {
    echo "* Verifying system disk..."

    local disk="$(lsblk --bytes --json /dev/${DISK_NAME})"
    log_and_reboot_on_error "${?}" "Unable to fetch disk information."

    local size=$(echo ${disk} | jq -r --arg logicalname "${DISK_NAME}" '.[][] | select(.name==$logicalname) | .size')
    log_and_reboot_on_error "${?}" "Unable to extract disk size."

    if [ "${size}" -gt "${DISK_SIZE}" ]; then
        echo "Disk size (${size} bytes) meets system requirements."
    else
        log_and_reboot_on_error "1" "Disk size (${size} bytes) does NOT meet system requirements."
    fi
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    verify_cpu
    verify_disk
    verify_memory
    log_end
}

main
