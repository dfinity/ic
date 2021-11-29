#!/usr/bin/env bash

# Tear-down an IC deployment.
#
# This script takes one positional argument:
#   <deployment_identifier>: The deployment referenced in `/testnet/env/${deployment}`
#

set -eEuo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Collapse (hide) this script's output in the gitlab job log
echo -e "\e[0Ksection_start:$(date +%s):icos_destroy.sh[collapsed=true]\r\e[0KClick here to see details from the testnet destroy script: icos_destroy.sh."

function exit_usage() {
    if (($# < 1)); then
        echo >&2 "Usage: icos_destroy.sh [--hosts-ini <hosts_override.ini>] <deployment_name>"
        echo >&2 "    --hosts-ini <hosts_override.ini> Override the default ansible hosts.ini to set different testnet configuration"

        exit 1
    fi
}

deployment=""
ANSIBLE_ARGS=""
HOSTS_INI_FILENAME="${HOSTS_INI_FILENAME:-hosts.ini}"

while [ $# -gt 0 ]; do
    case "${1}" in
        --ansible-args)
            if [[ -z "${2:-}" ]]; then exit_usage; fi
            ANSIBLE_ARGS="${ANSIBLE_ARGS} ${2:-}"
            shift
            ;;
        --hosts-ini)
            if [[ -z "${2:-}" ]]; then exit_usage; fi
            HOSTS_INI_FILENAME="${2}"
            shift
            ;;
        -?*) exit_usage ;;
        *) deployment="$1" ;;
    esac
    shift
done

if [[ -z "$deployment" ]]; then
    echo "ERROR: No deployment specified."
    exit_usage
fi

# This environment variable will be picked up by the Ansible inventory generation script.
# No further action is required to use the custom HOSTS_INI file.
export HOSTS_INI_FILENAME
hosts_ini_file_path="$REPO_ROOT/testnet/env/$deployment/$HOSTS_INI_FILENAME"
if [[ ! -f $hosts_ini_file_path ]]; then
    echo >&2 "The Ansible inventory file does not exist, aborting: $hosts_ini_file_path"
    exit 1
fi

echo "Destroying the IC deployment $deployment"

cd "$REPO_ROOT"/testnet/ansible

INVENTORY=$REPO_ROOT/testnet/env/$deployment/hosts
ANSIBLE="ansible-playbook -i "$INVENTORY" $ANSIBLE_ARGS "

$ANSIBLE icos_network_redeploy.yml -e ic_state="destroy"

$ANSIBLE ic_p8s_network_destroy.yml
$ANSIBLE ic_p8s_service_discovery_destroy.yml

echo -e "\e[0Ksection_end:$(date +%s):icos_destroy.sh\r\e[0K"
