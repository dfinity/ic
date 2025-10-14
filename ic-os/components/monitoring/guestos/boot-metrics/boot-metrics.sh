#!/bin/bash

set -e

# Startup Timing Metrics for Node Exporter

source /opt/ic/bin/logging.sh

METRICS_DIR="/run/node_exporter/collector_textfile"
METRICS_FILE="${METRICS_DIR}/guestos_startup.prom"

# --- Metric Writing Helper Functions ---

# Writes metric headers (# HELP and # TYPE) to the metrics file.
# Globals:
#   METRICS_FILE
# Arguments:
#   $1: Metric name
#   $2: Help text
#   $3: Metric type (e.g., gauge, counter)
write_metric_header() {
    local name="$1"
    local help="$2"
    local type="$3"

    echo "# HELP ${name} ${help}" >> "${METRICS_FILE}"
    echo "# TYPE ${name} ${type}" >> "${METRICS_FILE}"
}

# Appends a metric value (with optional labels) to the metrics file.
# Globals:
#   METRICS_FILE
# Arguments:
#   $1: Metric name
#   $2: Labels (e.g., '{unit="foo"}') or an empty string for no labels.
#   $3: Metric value
append_metric() {
    local name="$1"
    local labels="$2"
    local value="$3"

    echo "${name}${labels} ${value}" >> "${METRICS_FILE}"
}

convert_time_to_seconds() {
    local time_str="$1"
    local minutes=0
    local seconds=0
    local milliseconds=0

    # Create a working copy to strip parts as we parse them
    local work_str="$time_str"

    if [[ "$work_str" == *min* ]]; then
        minutes=$(echo "$work_str" | sed -n 's/^\([0-9.]\+\)min.*$/\1/p')
        work_str=$(echo "$work_str" | sed 's/^[0-9.]\+min \?//')
    fi

    if [[ "$work_str" == *ms* ]]; then
        milliseconds=$(echo "$work_str" | sed -n 's/^\([0-9.]\+\)ms.*$/\1/p')
        # This part of the string is now handled, clear it.
        work_str=""
    fi

    if [[ "$work_str" == *s* ]]; then
        seconds=$(echo "$work_str" | sed 's/s$//')
    fi

    awk -v min="${minutes:-0}" -v sec="${seconds:-0}" -v ms="${milliseconds:-0}" \
        'BEGIN { printf "%.4f\n", (min * 60) + sec + (ms / 1000) }'
}

# --- Metric Collection Functions ---

function get_startup_timings() {
    # Parse systemd-analyze output to get the time taken for the entire startup.
    local output_line
    output_line=$(systemd-analyze | head -n 1)

    local kernel_str
    kernel_str=$(echo "$output_line" | sed -n 's/.* in \(.*\) (kernel).*/\1/p')
    local userspace_str
    userspace_str=$(echo "$output_line" | sed -n 's/.* + \(.*\) (userspace).*/\1/p')
    local total_str
    total_str=$(echo "$output_line" | sed -n 's/.* = \(.*\)$/\1/p')

    local kernel_seconds
    kernel_seconds=$(convert_time_to_seconds "$kernel_str")
    local userspace_seconds
    userspace_seconds=$(convert_time_to_seconds "$userspace_str")
    local total_seconds
    total_seconds=$(convert_time_to_seconds "$total_str")

    write_log "Startup took ${total_seconds} seconds (kernel: ${kernel_seconds}, userspace: ${userspace_seconds})"

    # Kernel boot time metric
    local kernel_metric_name="guestos_boot_kernel_seconds"
    write_metric_header "$kernel_metric_name" "Time spent in the kernel during startup" "gauge"
    append_metric "$kernel_metric_name" "" "$kernel_seconds"

    # Userspace boot time metric
    local userspace_metric_name="guestos_boot_userspace_seconds"
    write_metric_header "$userspace_metric_name" "Time spent in userspace during startup" "gauge"
    append_metric "$userspace_metric_name" "" "$userspace_seconds"

    # Total boot time metric
    local total_metric_name="guestos_boot_total_seconds"
    write_metric_header "$total_metric_name" "Total time spent until startup finished" "gauge"
    append_metric "$total_metric_name" "" "$total_seconds"
}

function get_slowest_services() {
    # Define the metric metadata once.
    local metric_name="guestos_boot_service_seconds"
    local metric_help="Time spent for the given systemd unit to start"
    local metric_type="gauge"

    # Write the header for this metric series just once before the loop.
    write_metric_header "$metric_name" "$metric_help" "$metric_type"

    # Process the top 10 slowest services.
    systemd-analyze blame | head -n 10 | while read -r time unit; do
        local t_seconds
        t_seconds=$(convert_time_to_seconds "$time")

        # Sanitize the unit name to be a valid label value.
        local name
        name=$(echo "$unit" | tr '.' '_' | tr -c '[:alnum:]_' '_')

        append_metric "$metric_name" "{unit=\"${name}\"}" "$t_seconds"
    done
}

function main() {
    # Start with an empty metrics file for this run.
    > "${METRICS_FILE}"

    write_log "Generating GuestOS startup metrics..."
    get_startup_timings
    get_slowest_services
    write_log "Finished generating metrics to ${METRICS_FILE}"
}

main
