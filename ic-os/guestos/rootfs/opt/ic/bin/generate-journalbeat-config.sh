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

if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
    # Covert string into comma separated array
    journalbeat_hosts_array=$(for host in ${JOURNALBEAT_HOSTS}; do echo -n "\"${host}\", "; done | sed -E "s@, \$@@g")
    sed -e "s@{{ journalbeat_hosts }}@${journalbeat_hosts_array}@" "${IN_FILE}" >"${OUT_FILE}"
fi
