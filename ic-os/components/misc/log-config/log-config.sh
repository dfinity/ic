#!/bin/bash

CONFIG_DIR="/boot/config"
if [[ "$1" == "hostos" ]]; then
    CONFIG_OBJECT="/boot/config/config.json"
elif [[ "$1" == "guestos" ]]; then
    CONFIG_OBJECT="/run/config/config.json"
else
    echo "ERROR: Invalid environment: $1"
    exit 1
fi

log_directory_structure() {
    local dir=$1
    if [[ -d "$dir" ]]; then
        echo "Logging directory structure of $dir:"
        echo "$(ls -R "$dir")"
        echo "----- End of directory structure for $dir -----"
    else
        echo "ERROR: Directory not found: $dir"
    fi
}

log_file_contents() {
    local file=$1
    local filename=$(basename "$file")

    if [[ -f "$file" ]]; then
        echo "Logging contents of $filename:"
        echo "$(cat "$file")"
        echo "----- End of $filename -----"
    else
        echo "ERROR: File not found: $file"
    fi
}

echo "Logging config partition"
log_directory_structure "$CONFIG_DIR"
log_file_contents "$CONFIG_OBJECT"
