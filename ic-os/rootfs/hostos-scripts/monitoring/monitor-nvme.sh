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
if ! command -v nvme >/dev/null 2>&1; then
    echo "${0##*/}: LOGIC ERROR. nvme not installed" >&2
    exit 1
fi

write_help() {
    local name="nvme_$1"
    local help=$2
    local type=$3

    echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}"
}

write_line() {
    local name="nvme_$1"
    local label=$2
    local value=$3

    if [[ -n "${value}" ]]; then
        echo -e "${name}${label} ${value}"
    fi
}

# Set up the data to read from once
device_list="$(nvme list -o json | jq -r '.Devices | .[].DevicePath')"

declare -a disk_infos
declare -a disk_names
for device in ${device_list}; do
    disk_infos+=("$(nvme smart-log -o json "${device}")")
    disk_names+=("${device##*/}")
done
max_disk_index=$(("${#disk_names[@]}" - 1))

# Wrap in code block to reroute all output
{

    # Get the nvme-cli version
    nvme_version="$(nvme --version | awk '$1 == "nvme" {print $3}')"
    write_line "nvmecli_version" \
        "{version=\"$nvme_version\"}" \
        "1" \
        "NVMe CLI version" \
        ""

    # For each metric:
    #   Write help text
    #   For each NVMe device:
    #     write line of data
    # Descriptions modified from
    ## https://www.hugdiy.com/blog/really-understand-ssd-from-the-health-data-of-nvme-ssd-smart
    ## https://nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf
    # Temperature: temperature is in Kelvin, we want Celsius. Convert.
    write_help "temperature_celsius" \
        "Temperature in Celsius" \
        "gauge"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_temperature="$(echo "${disk_info}" | jq '.temperature - 273.15')"
        write_line "temperature_celsius" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_temperature}"
    done

    # Available Spare: Contains a normalized percentage (0 to 100%) of the remaining spare capacity available.
    write_help "available_spare_ratio" \
        "Available spare flash memory blocks" \
        "gauge"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_available_spare="$(echo "${disk_info}" | jq '.avail_spare / 100')"
        write_line "available_spare_ratio" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_available_spare}"
    done

    # Available Spare Threshold: when available spare space is lower than the threshold, an alert will be given to remind the user that the remaining life of flash memory is insufficient, and the hard disk should be replaced.
    write_help "available_spare_threshold_ratio" \
        "Available spare threshold" \
        "gauge"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_available_spare_threshold="$(echo "${disk_info}" | jq '.spare_thresh / 100')"
        write_line "available_spare_threshold_ratio" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_available_spare_threshold}"
    done

    # Percentage Used: Vendor specific estimate of the percentage of NVM subsystem life used based on the actual usage and the manufacturer’s prediction of NVM life. A value of 100 indicates that the estimated endurance of the NVM in the NVM subsystem has been consumed, but may not indicate an NVM subsystem failure. The value is allowed to exceed 100. Percentages greater than 254 shall be represented as 255. This value shall be updated once per power-on hour (when the controller is not in a sleep state). Refer to the JEDEC JESD218A standard for SSD device life and endurance measurement techniques.
    write_help "percent_used" \
        "Percent Used" \
        "gauge"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_percent_used="$(echo "${disk_info}" | jq '.percent_used')"
        write_line "percent_used" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_percent_used}"
    done

    # Critical Warning: bits set: 1, 2, 3, 4.
    # If bit 1 is set the disk is overheated (or underheated).
    # If bit 2 is set there is a serious error in flash memory, leading to reliability degradation, which should be considered to be replaced.
    # If bit 3 is set flash memory has been placed in the read-only mode. The service life is at its end and the disk is locked to protect user data.
    # If bit 4 is set  the volatile memory backup device has failed. This field is only valid if the controller has a volatile memory backup solution.
    write_help "critical_warning" \
        "Critical warning code" \
        "gauge"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_critical_warning="$(echo "${disk_info}" | jq '.critical_warning')"
        write_line "critical_warning" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_critical_warning}"
    done

    # Media and Data Integrity Errors: Contains the number of occurrences where the controller detected an unrecovered data integrity error. Errors such as uncorrectable ECC, CRC checksum failure, or LBA tag mismatch are included in this field.
    write_help "media_errors_total" \
        "Media and Data Integrity Errors" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_media_errors="$(echo "${disk_info}" | jq '.media_errors')"
        write_line "media_errors_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_media_errors}"
    done

    # Number of Error Information Log Entries: Contains the number of Error Information log entries over the life of the controller.
    write_help "num_err_log_entries_total" \
        "Number of Error Information Log Entries" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_num_err_log_entries="$(echo "${disk_info}" | jq '.num_err_log_entries')"
        write_line "num_err_log_entries_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_num_err_log_entries}"
    done

    # Power Cycles: number of power cycles
    write_help "power_cycles_total" \
        "Power Cycles" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_power_cycles="$(echo "${disk_info}" | jq '.power_cycles')"
        write_line "power_cycles_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_power_cycles}"
    done

    # Power On Time: This may not include time that the controller was powered and in a non-operational power state. Value is in seconds.
    write_help "power_on_seconds_total" \
        "Power On Time in Seconds" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_power_on_hours="$(echo "${disk_info}" | jq '.power_on_hours')"
        write_line "power_on_seconds_total" \
            "{device=\"${disk_names[$i]}\"}" \
            $(("${value_power_on_hours}" * 60 * 60))
    done

    # Controller Busy Time: Contains the amount of time the controller is busy with I/O commands. The controller is busy when there is a command outstanding to an I/O Queue (specifically, a command was issued via an I/O Submission Queue Tail doorbell write and the corresponding completion queue entry has not been posted yet to the associated I/O Completion Queue). Value is in seconds.
    write_help "controller_busy_time_seconds" \
        "Total Time Controller was Busy with I/O commands in Seconds" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_controller_busy_time="$(echo "${disk_info}" | jq '.controller_busy_time')"
        write_line "controller_busy_time_seconds" \
            "{device=\"${disk_names[$i]}\"}" \
            $(("${value_controller_busy_time}" * 60))
    done

    # Data Units Written: Contains the number of 512 byte data units the host has written to the controller; this value does not include metadata. This value is reported in thousands (i.e., a value of 1 corresponds to 1000 units of 512 bytes written) and is rounded up. When the LBA size is a value other than 512 bytes, the controller shall convert the amount of data written to 512 byte units. For the NVM command set, logical blocks written as part of Write operations shall be included in this value. Write Uncorrectable commands shall not impact this value.
    write_help "data_units_written_total" \
        "1000 * 512 Byte Data Units Written" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_data_units_written="$(echo "${disk_info}" | jq '.data_units_written')"
        write_line "data_units_written_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_data_units_written}"
    done

    # Data Units Read: Contains the number of 512 byte data units the host has read from the controller; this value does not include metadata. This value is reported in thousands (i.e., a value of 1 corresponds to 1000 units of 512 bytes read) and is rounded up. When the LBA size is a value other than 512 bytes, the controller shall convert the amount of data read to 512 byte units. For the NVM command set, logical blocks read as part of Compare and Read operations shall be included in this value.
    write_help "data_units_read_total" \
        "1000 * 512 Byte Data Units Read" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_data_units_read="$(echo "${disk_info}" | jq '.data_units_read')"
        write_line "data_units_read_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_data_units_read}"
    done

    # Host Read Commands: Contains the number of read commands completed by the controller. For the NVM command set, this is the number of Compare and Read commands.
    write_help "host_read_commands_total" \
        "Host Read Commands" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_host_read_commands="$(echo "${disk_info}" | jq '.host_read_commands')"
        write_line "host_read_commands_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_host_read_commands}"
    done

    # Host Write Commands: Contains the number of write commands completed by the controller. For the NVM command set, this is the number of Write commands.
    write_help "host_write_commands_total" \
        "Host Write Commands" \
        "counter"
    for i in $(seq 0 "${max_disk_index}"); do
        disk_info="${disk_infos[$i]}"
        value_host_write_commands="$(echo "${disk_info}" | jq '.host_write_commands')"
        write_line "host_write_commands_total" \
            "{device=\"${disk_names[$i]}\"}" \
            "${value_host_write_commands}"
    done

    # textfile_collector needs a newline to be happy
    echo ''
} | sponge "${METRICS_DIR}/nvme_metrics.prom"
# sponge takes all of stdin and writes it to the file atomically
