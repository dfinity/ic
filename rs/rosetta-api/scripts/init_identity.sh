#!/usr/bin/env bash

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TEMP_DIR="$SCRIPT_DIR/tmp" # need a persistent directory from within dev container
ID_WHOAMI="upgrade_test_id"
ID_TEMP_DIR="$TEMP_DIR/dfx/identity/$ID_WHOAMI"
ID_HOME_DIR="$HOME/.config/dfx/identity/$ID_WHOAMI"

# Creates and persist a new identity
# such that disconnecting from the
# dev container won't result in losing
# the identity
function init_identity {
    dfx identity whoami # forces dfx initialization
    # if the identity is already in the home directory
    # then skip the process
    if [ -d "$ID_HOME_DIR" ]; then
        echo "Found $ID_WHOAMI identity in $ID_HOME_DIR"
    elif [ -d "$ID_TEMP_DIR" ]; then
        echo "Found dfx directory $ID_TEMP_DIR, I'm going to copy it to $ID_HOME_DIR"
        mkdir -p "$ID_HOME_DIR"
        cp -r "$ID_TEMP_DIR/." "$ID_HOME_DIR/"
    else
        echo "No identity directory found, I'm going to create a new $ID_WHOAMI identity and persist it"
        dfx identity new "$ID_WHOAMI" --disable-encryption
        mkdir -p "$ID_TEMP_DIR"
        cp -r "$ID_HOME_DIR/." "$ID_TEMP_DIR/"
    fi
    dfx identity use "$ID_WHOAMI"
}
