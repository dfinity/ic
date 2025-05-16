#!/bin/bash

set -o errexit
set -o nounset

METRICS_DIR="/run/node_exporter/collector_textfile"

# Check if we are root
if [ "$EUID" -ne 0 ]; then
    echo "${0##*/}: LOGIC ERROR - must be run as root!" >&2
    exit 1
fi

# Check if programs are installed
if ! command -v ipmitool >/dev/null 2>&1; then
    echo "${0##*/}: LOGIC ERROR. ipmitool not installed" >&2
    exit 1
fi

write_line() {
    local name="power_$1"
    local value=$2
    local help=$3
    local type=$4

    if [[ -n "${value}" ]]; then
        echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name} ${value}\n"
    fi
}

# Wrap in code block to reroute all output
{

    # Example output:
    # # sudo ipmitool dcmi power reading

    #    Instantaneous power reading:                   240 Watts
    #    Minimum during sampling period:                132 Watts
    #    Maximum during sampling period:                384 Watts
    #    Average power reading over sample period:      204 Watts
    #    IPMI timestamp:                           03/06/2025 07:40:35 UTC    Sampling period:                          00000001 Seconds.
    #    Power reading state is:                   activated

    ipmi_output="$(ipmitool dcmi power reading 2>/dev/null)"

    value=$(echo "${ipmi_output}" | grep "Instantaneous power reading:" | awk '{print $4}')
    value=${value:-"-1"}
    write_line "instantaneous_watts" \
        "${value}" \
        "Instantaneous power reading, Watts" \
        "gauge"

    value=$(echo "${ipmi_output}" | grep "Average power reading over sample period:" | awk '{print $7}')
    value=${value:-"-1"}
    write_line "average_watts" \
        "${value}" \
        "Average power reading, Watts" \
        "gauge"

    value=$(echo "${ipmi_output}" | grep "Sampling period:" | awk '{print $8}')
    value=${value:-"-1"}
    write_line "sampling_period_seconds" \
        "${value}" \
        "Power sampling period, seconds" \
        "gauge"

} | sponge "${METRICS_DIR}/power_metrics.prom"
# sponge takes all of stdin and writes it to the file atomically
