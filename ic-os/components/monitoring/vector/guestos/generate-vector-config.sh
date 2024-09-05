#!/bin/bash

# Substitute correct configuration parameters into vector.yml.

function usage() {
    cat <<EOF
Usage:
  generate-vector-config [-j vector.conf] \\
    -i vector.yaml.template \\
    -o vector.yaml

  Generate vector config from template file.

  -i infile: input vector.yaml.template file
  -j vector.conf: Optional, vector configuration description file
  -o outfile: output vector.yaml file
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
            "elasticsearch_hosts") elasticsearch_hosts="${value}" ;;
            "prometheus_hosts") prometheus_hosts="${value}" ;;
            "vector_tls") vector_tls="${value}" ;;
        esac
    done <"$1"
}

while getopts "i:j:k:o:" OPT; do
    case "${OPT}" in
        i)
            IN_FILE="${OPTARG}"
            ;;
        j)
            VECTOR_CONFIG_FILE="${OPTARG}"
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

if [ "${VECTOR_CONFIG_FILE}" != "" ] && [ -e "${VECTOR_CONFIG_FILE}" ]; then
    read_variables "${VECTOR_CONFIG_FILE}"
fi
VECTOR_TLS_PATH="${vector_tls:-/run/ic-node/etc/vector}"

ELASTICSEARCH_HOSTS="${elasticsearch_hosts}"
PROMETHEUS_HOSTS="${prometheus_hosts}"

if [ "${ELASTICSEARCH_HOSTS}" != "" ]; then
    # Covert string into comma separated array
    elasticsearch_hosts_array=$(for host in ${ELASTICSEARCH_HOSTS}; do echo -n "\"https://${host}\", "; done | sed -E "s@, \$@@g")
    sed -e "s@{{ elasticsearch_hosts }}@${elasticsearch_hosts_array}@" "${IN_FILE}" >"${OUT_FILE}"

    sink_name=elasticsearch
    sink_tls_key="${VECTOR_TLS_PATH}/${sink_name}.key"
    sink_tls_crt="${VECTOR_TLS_PATH}/${sink_name}.crt"
    if [ -f "${sink_tls_key}" ] && [ -f "${sink_tls_crt}" ]; then
        echo '      key_file: '${sink_tls_key} >>"${OUT_FILE}"
        echo '      crt_file: '${sink_tls_crt} >>"${OUT_FILE}"
    fi

    if [ "${PROMETHEUS_HOSTS}" != "" ]; then

        read -r -d '' PROMETHEUS_SINK << EOF
  {{ prometheus_name }}:
    type: prometheus_remote_write
    inputs:
      - guestos_node_exporter
      - guestos_replica
      - metrics_proxy
    healthcheck:
      enabled: false    # Required due to http prometheus_remote_write call to vm returns 204 instead of 200
    endpoint: https://{{ prometheus_host }}
    tls:
      verify_certificate: false
EOF

        prometheus_sinks_array=$(for data in ${PROMETHEUS_HOSTS}; do
            sink_name=$(echo ${data} | cut -d_ -f1)
            sink_host=$(echo ${data} | cut -d_ -f2)
            path=$(echo ${data} | cut -d_ -f3)
            sink_path="${path:-/api/v1/write}"
            echo "${PROMETHEUS_SINK}" | sed -e "s@{{ prometheus_name }}@  ${sink_name}@" -e "s@{{ prometheus_host }}@${sink_host}@" -

            sink_tls_key="${VECTOR_TLS_PATH}/${sink_name}.key"
            sink_tls_crt="${VECTOR_TLS_PATH}/${sink_name}.crt"
            if [ -f "${sink_tls_key}" ] && [ -f "${sink_tls_crt}" ]; then
                echo '      key_file: '${sink_tls_key}
                echo '      crt_file: '${sink_tls_crt}
            fi
        done)
        INPUT=$(cat "${OUT_FILE}")
        echo "${INPUT}" | prometheus_sinks=${prometheus_sinks_array} envsubst > "${OUT_FILE}"
    fi
fi
