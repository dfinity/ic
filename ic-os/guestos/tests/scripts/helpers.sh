#!/bin/bash

function retry_command() {
    MAX=$1
    shift
    NUM=0

    while ! "$@"; do
        NUM=$(($NUM + 1))
        if [[ $NUM -ge $MAX ]]; then
            echo "❌ Failed to run command '$@' - tried $NUM times. Aborting"
            exit 1
        fi
        sleep 5
    done

}
