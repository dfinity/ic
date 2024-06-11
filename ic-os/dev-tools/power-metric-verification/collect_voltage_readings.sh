#!/bin/bash

output_file="voltage_readings.txt"
sudo rm "$output_file"

collect_voltage_readings() {
    duration_in_minutes=$1
    end_time=$(($(date +%s) + duration_in_minutes * 60))

    while [ $(date +%s) -lt $end_time ]; do
        sudo ipmitool dcmi power reading >>$output_file
        sleep 10s
    done
}

# duration_in_minutes is the maximum amount of time to collect voltage readings
duration_in_minutes=120
collect_voltage_readings $duration_in_minutes &
voltage_readings_pid=$!

# alternating cycles of stress tests and rest periods in order to get voltage readings under different conditions.
for i in 10 5 10 5 10; do
    timeout "${i}m" stress-ng --sequential "$(nproc)"
    sleep "${i}m"
done

sudo kill $voltage_readings_pid

python3 parse_voltage_readings.py voltage_readings.txt
