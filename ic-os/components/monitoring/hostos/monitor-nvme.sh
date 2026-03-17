#!/bin/bash

set -o errexit
set -o nounset

source /opt/ic/bin/metrics.sh

METRICS_FAMILY="nvme_metrics"

# Check if we are root
if [ "$EUID" -ne 0 ]; then
    echo "${0##*/}: LOGIC ERROR - must be run as root!" >&2
    exit 1
fi

# Check if programs are installed
if ! command -v nvme >/dev/null 2>&1; then
    echo "${0##*/}: LOGIC ERROR. nvme not installed" >&2
    exit 1
fi

# Set up the data to read from once
device_list="$(nvme list -o json | jq -r '.Devices | .[].DevicePath')"

declare -a disk_infos
declare -a disk_names
for device in ${device_list}; do
    disk_infos+=("$(nvme smart-log -o json "${device}")")
    disk_names+=("${device##*/}")
done
max_disk_index=$(("${#disk_names[@]}" - 1))

clear_metrics "$METRICS_FAMILY"

# NVMe CLI version
nvme_version="$(nvme --version | awk '$1 == "nvme" {print $3}')"
write_metric_header "$METRICS_FAMILY" "nvme_nvmecli_version" "NVMe CLI version" "gauge"
append_metric "$METRICS_FAMILY" "nvme_nvmecli_version" "{version=\"$nvme_version\"}" "1"

# Descriptions modified from
## https://www.hugdiy.com/blog/really-understand-ssd-from-the-health-data-of-nvme-ssd-smart
## https://nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf

# Temperature: temperature is in Kelvin, we want Celsius. Convert.
write_metric_header "$METRICS_FAMILY" "nvme_temperature_celsius" "Temperature in Celsius" "gauge"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.temperature - 273.15')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_temperature_celsius" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Available Spare: Contains a normalized percentage (0 to 100%) of the remaining spare capacity available.
write_metric_header "$METRICS_FAMILY" "nvme_available_spare_ratio" "Available spare flash memory blocks" "gauge"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.avail_spare / 100')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_available_spare_ratio" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Available Spare Threshold: when available spare space is lower than the threshold, an alert will be given
# to remind the user that the remaining life of flash memory is insufficient, and the hard disk should be replaced.
write_metric_header "$METRICS_FAMILY" "nvme_available_spare_threshold_ratio" "Available spare threshold" "gauge"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.spare_thresh / 100')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_available_spare_threshold_ratio" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Percentage Used: Vendor specific estimate of the percentage of NVM subsystem life used based on the actual
# usage and the manufacturer's prediction of NVM life. A value of 100 indicates that the estimated endurance
# of the NVM in the NVM subsystem has been consumed, but may not indicate an NVM subsystem failure. The value
# is allowed to exceed 100.
write_metric_header "$METRICS_FAMILY" "nvme_percent_used" "Percent Used" "gauge"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.percent_used')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_percent_used" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Critical Warning: bits set: 1, 2, 3, 4.
# If bit 1 is set the disk is overheated (or underheated).
# If bit 2 is set there is a serious error in flash memory, leading to reliability degradation.
# If bit 3 is set flash memory has been placed in read-only mode.
# If bit 4 is set the volatile memory backup device has failed.
write_metric_header "$METRICS_FAMILY" "nvme_critical_warning" "Critical warning code" "gauge"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.critical_warning')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_critical_warning" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Media and Data Integrity Errors: Contains the number of occurrences where the controller detected
# an unrecovered data integrity error.
write_metric_header "$METRICS_FAMILY" "nvme_media_errors_total" "Media and Data Integrity Errors" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.media_errors')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_media_errors_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Number of Error Information Log Entries: Contains the number of Error Information log entries
# over the life of the controller.
write_metric_header "$METRICS_FAMILY" "nvme_num_err_log_entries_total" "Number of Error Information Log Entries" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.num_err_log_entries')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_num_err_log_entries_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Power Cycles: number of power cycles
write_metric_header "$METRICS_FAMILY" "nvme_power_cycles_total" "Power Cycles" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.power_cycles')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_power_cycles_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Power On Time: This may not include time that the controller was powered and in a non-operational
# power state. Value is in seconds.
write_metric_header "$METRICS_FAMILY" "nvme_power_on_seconds_total" "Power On Time in Seconds" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.power_on_hours')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_power_on_seconds_total" "{device=\"${disk_names[$i]}\"}" $(("${value}" * 60 * 60))
done

# Controller Busy Time: Contains the amount of time the controller is busy with I/O commands. Value is in seconds.
write_metric_header "$METRICS_FAMILY" "nvme_controller_busy_time_seconds" "Total Time Controller was Busy with I/O commands in Seconds" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.controller_busy_time')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_controller_busy_time_seconds" "{device=\"${disk_names[$i]}\"}" $(("${value}" * 60))
done

# Data Units Written: Contains the number of 512 byte data units the host has written to the controller.
# This value is reported in thousands (i.e., a value of 1 corresponds to 1000 units of 512 bytes written).
write_metric_header "$METRICS_FAMILY" "nvme_data_units_written_total" "1000 * 512 Byte Data Units Written" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.data_units_written')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_data_units_written_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Data Units Read: Contains the number of 512 byte data units the host has read from the controller.
# This value is reported in thousands (i.e., a value of 1 corresponds to 1000 units of 512 bytes read).
write_metric_header "$METRICS_FAMILY" "nvme_data_units_read_total" "1000 * 512 Byte Data Units Read" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.data_units_read')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_data_units_read_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Host Read Commands: Contains the number of read commands completed by the controller.
write_metric_header "$METRICS_FAMILY" "nvme_host_read_commands_total" "Host Read Commands" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.host_read_commands')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_host_read_commands_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done

# Host Write Commands: Contains the number of write commands completed by the controller.
write_metric_header "$METRICS_FAMILY" "nvme_host_write_commands_total" "Host Write Commands" "counter"
for i in $(seq 0 "${max_disk_index}"); do
    value="$(echo "${disk_infos[$i]}" | jq '.host_write_commands')"
    [[ -n "${value}" ]] && append_metric "$METRICS_FAMILY" "nvme_host_write_commands_total" "{device=\"${disk_names[$i]}\"}" "${value}"
done
