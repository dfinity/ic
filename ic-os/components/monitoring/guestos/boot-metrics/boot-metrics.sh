#!/bin/bash

set -e

# Startup Timing Metrics for Node Exporter

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

METRICS_FAMILY="guestos_startup"

convert_time_to_seconds() {
    local time_str="$1"
    local hours=0
    local minutes=0
    local seconds=0
    local milliseconds=0

    # create a working copy to strip parts as we parse them
    local work_str="$time_str"

    # parse hours
    if [[ "$work_str" == *h* ]]; then
        hours=$(echo "$work_str" | sed -n 's/^\([0-9.]\+\)h.*$/\1/p')
        work_str=$(echo "$work_str" | sed 's/^[0-9.]\+h \?//')
    fi

    # parse minutes from the remainder
    if [[ "$work_str" == *min* ]]; then
        minutes=$(echo "$work_str" | sed -n 's/^\([0-9.]\+\)min.*$/\1/p')
        work_str=$(echo "$work_str" | sed 's/^[0-9.]\+min \?//')
    fi

    # parse milliseconds from the remainder
    if [[ "$work_str" == *ms* ]]; then
        milliseconds=$(echo "$work_str" | sed -n 's/^\([0-9.]\+\)ms.*$/\1/p')
        # This part of the string is now handled, clear it.
        work_str=""
    fi

    # parse seconds from the remainder
    if [[ "$work_str" == *s* ]]; then
        seconds=$(echo "$work_str" | sed 's/s$//')
    fi

    # calculate the total
    awk -v h="${hours:-0}" -v min="${minutes:-0}" -v sec="${seconds:-0}" -v ms="${milliseconds:-0}" \
        'BEGIN { printf "%.4f\n", (h * 3600) + (min * 60) + sec + (ms / 1000) }'
}

function get_startup_timings() {
    # Parse systemd-analyze output to get the time taken for the entire startup.
    local output_line=$(systemd-analyze | head -n 1)

    local kernel_str=$(echo "$output_line" | sed -n 's/.* in \(.*\) (kernel).*/\1/p')
    local userspace_str=$(echo "$output_line" | sed -n 's/.* + \(.*\) (userspace).*/\1/p')
    local total_str=$(echo "$output_line" | sed -n 's/.* = \(.*\)$/\1/p')

    local kernel_seconds=$(convert_time_to_seconds "$kernel_str")
    local userspace_seconds=$(convert_time_to_seconds "$userspace_str")
    local total_seconds=$(convert_time_to_seconds "$total_str")

    write_log "Startup took ${total_seconds} seconds (kernel: ${kernel_seconds}, userspace: ${userspace_seconds})"

    # Kernel boot time metric
    local kernel_metric_name="guestos_boot_kernel_seconds"
    write_metric_header "$METRICS_FAMILY" "$kernel_metric_name" "Time spent in the kernel during startup" "gauge"
    append_metric "$METRICS_FAMILY" "$kernel_metric_name" "" "$kernel_seconds"

    # Userspace boot time metric
    local userspace_metric_name="guestos_boot_userspace_seconds"
    write_metric_header "$METRICS_FAMILY" "$userspace_metric_name" "Time spent in userspace during startup" "gauge"
    append_metric "$METRICS_FAMILY" "$userspace_metric_name" "" "$userspace_seconds"

    # Total boot time metric
    local total_metric_name="guestos_boot_total_seconds"
    write_metric_header "$METRICS_FAMILY" "$total_metric_name" "Total time spent until startup finished" "gauge"
    append_metric "$METRICS_FAMILY" "$total_metric_name" "" "$total_seconds"
}

function get_slowest_services() {
    # Define the metric metadata once.
    local metric_name="guestos_boot_service_seconds"
    local metric_help="Time spent for the given systemd unit to start"
    local metric_type="gauge"

    # Write the header for this metric series just once before the loop.
    write_metric_header "$METRICS_FAMILY" "$metric_name" "$metric_help" "$metric_type"

    # Process the top 10 slowest services.
    systemd-analyze blame | head -n 10 | while read -r -a line_parts; do
        # Skip empty lines
        [ -z "${line_parts[0]}" ] && continue

        local unit="${line_parts[-1]}"
        local time_str="${line_parts[@]:0:${#line_parts[@]}-1}"

        # Trim leading/trailing whitespace from time_str
        time_str=$(echo "$time_str" | sed 's/^[ \t]*//;s/[ \t]*$//')

        local t_seconds=$(convert_time_to_seconds "$time_str")

        # Sanitize the unit name to be a valid label value.
        local name=$(echo "$unit" | tr '.' '_' | tr -c '[:alnum:]_' '_')

        append_metric "$METRICS_FAMILY" "$metric_name" "{unit=\"${name}\"}" "$t_seconds"
    done
}

function main() {
    # Start with an empty metrics file for this run.
    clear_metrics "$METRICS_FAMILY"

    write_log "Generating GuestOS startup metrics..."
    get_startup_timings
    get_slowest_services
    write_log "Finished generating metrics to ${METRICS_FAMILY}"
}

main
