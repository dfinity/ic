#!/bin/bash

set -o errexit
set -o nounset

source /opt/ic/bin/metrics.sh

METRICS_FAMILY="power_metrics"

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

clear_metrics "$METRICS_FAMILY"

# Example output:
# # sudo ipmitool dcmi power reading
#
#    Instantaneous power reading:                   240 Watts
#    Minimum during sampling period:                132 Watts
#    Maximum during sampling period:                384 Watts
#    Average power reading over sample period:      204 Watts
#    IPMI timestamp:                           03/06/2025 07:40:35 UTC
#    Sampling period:                          00000001 Seconds.
#    Power reading state is:                   activated

ipmi_output="$(ipmitool dcmi power reading 2>/dev/null)"

value=$(echo "${ipmi_output}" | grep "Instantaneous power reading:" | awk '{print $4}')
value=${value:-"-1"}
write_metric_header "$METRICS_FAMILY" "power_instantaneous_watts" "Instantaneous power reading, Watts" "gauge"
append_metric "$METRICS_FAMILY" "power_instantaneous_watts" "" "${value}"

value=$(echo "${ipmi_output}" | grep "Average power reading over sample period:" | awk '{print $7}')
value=${value:-"-1"}
write_metric_header "$METRICS_FAMILY" "power_average_watts" "Average power reading, Watts" "gauge"
append_metric "$METRICS_FAMILY" "power_average_watts" "" "${value}"

value=$(echo "${ipmi_output}" | grep "Sampling period:" | awk '{print $8}')
value=${value:-"-1"}
write_metric_header "$METRICS_FAMILY" "power_sampling_period_seconds" "Power sampling period, seconds" "gauge"
append_metric "$METRICS_FAMILY" "power_sampling_period_seconds" "" "${value}"
