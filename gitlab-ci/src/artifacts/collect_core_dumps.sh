#!/usr/bin/env bash

# Core dumps are stored in /tmp/core.*
# This script will collect the core dumps, for each create a backtrace using lldb
# and store the core dumps and the corresponding binaries in ${CI_PROJECT_DIR}/coredumps
#
# Notes:
#   - The script will only run if there are core dump files (/tmp/core.*)
#   - After the execution the core dump files are removed, making it cheap to call the script multiple times

SHELL=$(type -p bash)
export SHELL

cd "${CI_PROJECT_DIR}" || {
    echo "Fatal error, cannot enter the \$CI_PROJECT_DIR"
    exit 1
}

function process_single_core_file() {
    # Construct the basename (no directory) for the core dump file
    f_basename=$(basename "$1")

    # for each coredump print the backtrace using lldb, and upload it as an artifact
    lldb --core "$1" --one-line 'bt
    exit' | tee "coredumps/backtrace.${f_basename}.txt"

    # To enable the uploading of binaries (core dumps and executables),
    # set UPLOAD_BINARIES=true
    UPLOAD_BINARIES=false

    if $UPLOAD_BINARIES; then
        # Try to extract a list of executables used by this core dump
        EXEC_NAMES=$(lldb --core "$1" --one-line 'image list
        exit' | grep '^\[' | grep -v '/nix/' | grep -v 'vdso' | awk '{print $NF}')

        for exec_name in $EXEC_NAMES; do
            # gzip and artifact dependent executables, skipping the ones already done
            if [[ ! -f "coredumps/$(basename "$exec_name").gz" ]]; then
                gzip -c --no-name "${exec_name}" >"coredumps/$(basename "$exec_name").gz"
            fi
        done

        # Finally, gzip and artifact the core dump itself
        gzip -f --no-name "$1"
        mv "$1.gz" "coredumps/${f_basename}.gz"
    fi
}

# https://stackoverflow.com/questions/6363441/check-if-a-file-exists-with-wildcard-in-shell-script
if compgen -G "/tmp/core.*"; then
    echo "Found unprocessed core dumps."

    echo -e "\e[0Ksection_start:$(date +%s):collect_core_dumps[collapsed=true]\r\e[0KClick here to see backtraces for core dumps"
    set -x
    # Everything from coredumps/ will be uploaded as artifacts
    mkdir -p coredumps
    export -f process_single_core_file
    parallel --eta process_single_core_file ::: $(ls /tmp/core.*)
    # Enable this script to be called again with (almost) no cost
    rm /tmp/core.*
    set +x
    echo -e "\e[0Ksection_end:$(date +%s):collect_core_dumps\r\e[0K"
else
    echo "No unprocessed core dumps found."
fi
