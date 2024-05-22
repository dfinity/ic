#!/bin/bash

set -o nounset
set -o pipefail

# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh
METRICS_FILE="${METRICS_DIR}/firewall_counters.prom"

# List of counter names
counters=(
    "rate_limit_v4_counter ip"
    "connection_limit_v4_counter ip"
    "rate_limit_v6_counter ip6"
    "connection_limit_v6_counter ip6"
)

# Function to read a counter value
get_counter_value() {
    local counter_name=$1
    local address_family=$2
    nft list counter "${address_family}" filter "${counter_name}" | awk '/packets/ {print $2}'
}

# Clear the metrics file
>$METRICS_FILE

# Loop through all counter names and print their values
for counter in "${counters[@]}"; do
    # Split the tuple into counter_name and address_family using read
    IFS=' ' read -r counter_name address_family <<<"$counter"

    counter_value=$(get_counter_value "${counter_name}" "${address_family}")
    if [ -z "$counter_value" ]; then
        counter_value = 0
    fi

    cat >>"${METRICS_FILE}" <<EOF
# HELP ${counter_name} Total number of times the firewall rule has been applied.
# TYPE ${counter_name} counter
${counter_name} ${counter_value}
EOF

done

echo "Metrics written to ${METRICS_FILE}"
