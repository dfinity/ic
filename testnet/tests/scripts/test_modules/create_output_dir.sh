#!/usr/bin/env bash

# scenario test script module.
# Name: create_output_dir.sh
# Args: <results_dir>
# Roughly speaking, this script:
# - creates the output directory for the test

if (($# != 1)); then
    echo >&2 "Wrong number of arguments, please provide values for <results_dir>"
    exit 1
fi

results_dir="$1"

if [[ ! -d $results_dir ]]; then
    echo >&2 "'$results_dir' does not exist, will be created..."
    # creation happens then for experiment_dir below
fi

if [[ $results_dir != /* ]]; then
    echo >&2 "'$results_dir' is not an absolute path, converting to absolute..."
    results_dir="$PWD/$results_dir"
fi

mkdir -p "$results_dir"
