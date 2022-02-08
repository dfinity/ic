#!/bin/bash

# Substitute correct configuration parameters into journalbeat.yml.

function usage() {
    cat <<EOF
Usage:
  generate-journalbeat-config [-j journalbeat.conf] \\
    -i journalbeat.yml.template \\
    -o journalbeat.yml

  Generate journalbeat config from template file.

  -i infile: input journalbeat.yml.template file
  -j journalbeat.conf: Optional, journalbeat configuration description file
  -o outfile: output journalbeat.yml file
EOF
}

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "journalbeat_hosts") journalbeat_hosts="${value}" ;;
            "journalbeat_tags") journalbeat_tags="${value}" ;;
        esac
    done <"$1"
}

while getopts "i:j:k:o:" OPT; do
    case "${OPT}" in
        i)
            IN_FILE="${OPTARG}"
            ;;
        j)
            JOURNALBEAT_CONFIG_FILE="${OPTARG}"
            ;;
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "${IN_FILE}" == "" ] || [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

if [ "${JOURNALBEAT_CONFIG_FILE}" != "" ] && [ -e "${JOURNALBEAT_CONFIG_FILE}" ]; then
    read_variables "${JOURNALBEAT_CONFIG_FILE}"
fi

JOURNALBEAT_HOSTS="${journalbeat_hosts}"
JOURNALBEAT_TAGS="${journalbeat_tags}"

testnet_prefixes=(
    "2a00:fb01:400:42"
    "2607:fb58:9005:42"
    "2607:f6f0:3004:1"
    "2001:4d78:40d:0"
    "fd00:2:1:1"
)

MAINNET="telemetry01.mainnet.dfinity.network telemetry02.mainnet.dfinity.network telemetry03.mainnet.dfinity.network"
TESTNET="telemetry01.testnet.dfinity.network telemetry02.testnet.dfinity.network telemetry03.testnet.dfinity.network"

if [ -z "${JOURNALBEAT_HOSTS}" ] || (echo ${JOURNALBEAT_HOSTS} | grep -iE 'mainnet|mercury|stage' >/dev/null); then
    # Set default journalbeat hosts
    # Detect if this is a testnet node or a mainnet node
    ipv6_prefix="$(ip -6 addr show | awk '(/inet6/) && (! /fe80|::1/) { print $2 }' | cut -d: -f1-4)"
    # Default to mainnet:
    JOURNALBEAT_HOSTS="${MAINNET}"
    for testnet_prefix in ${testnet_prefixes[@]}; do
        if [ "$testnet_prefix" = "$ipv6_prefix" ]; then
            # If a testnet node, use this as the default instead:
            JOURNALBEAT_HOSTS="${TESTNET}"
        fi
    done
fi

# XXX
# This function is a temporary hack, it takes care of harmonizing the
# configuration on all nodes. To be removed before next node upgrade.
echo "journalbeat_hosts=${JOURNALBEAT_HOSTS}" >/boot/config/journalbeat.conf
# XXX

if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
    # Covert string into comma separated array
    journalbeat_hosts_array=$(for host in ${JOURNALBEAT_HOSTS}; do echo -n "\"${host}\", "; done | sed -E "s@, \$@@g")
    sed -e "s@{{ journalbeat_hosts }}@${journalbeat_hosts_array}@" "${IN_FILE}" >"${OUT_FILE}"
fi

if [ "${JOURNALBEAT_TAGS}" != "" ]; then
    # Covert string into comma separated array
    journalbeat_tags_array=$(for tag in ${JOURNALBEAT_TAGS}; do echo -n "\"${tag}\", "; done | sed -E "s@, \$@@g")
    sed -e "s@#{{ journalbeat_tags }}@tags: [${journalbeat_tags_array}]@" -i "${OUT_FILE}"
fi
