#!/bin/bash

# Substitute correct configuration parameters into filebeat.yml.

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  generate-filebeat-config -i filebeat.yml.template \\
    -o filebeat.yml

  Generate filebeat config from template file.

  -i infile: input filebeat.yml.template file
  -o outfile: output filebeat.yml file
EOF
}

function read_config_variables() {
    elasticsearch_hosts=$(get_config_value '.icos_settings.logging.elasticsearch_hosts')
    elasticsearch_tags=$(get_config_value '.icos_settings.logging.elasticsearch_tags')
}

while getopts "i:o:" OPT; do
    case "${OPT}" in
        i)
            IN_FILE="${OPTARG}"
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

read_config_variables

ELASTICSEARCH_HOSTS="${elasticsearch_hosts}"
ELASTICSEARCH_TAGS="${elasticsearch_tags}"

if [ "${ELASTICSEARCH_HOSTS}" != "" ] && [ "${ELASTICSEARCH_HOSTS}" != "null" ]; then
    # Covert string into comma separated array
    if [ "$(echo ${ELASTICSEARCH_HOSTS} | grep ':')" ]; then
        elasticsearch_hosts_array=$(for host in ${ELASTICSEARCH_HOSTS}; do echo -n "\"${host}\", "; done | sed -E "s@, \$@@g")
    else
        elasticsearch_hosts_array=$(for host in ${ELASTICSEARCH_HOSTS}; do echo -n "\"${host}:443\", "; done | sed -E "s@, \$@@g")
    fi
    sed -e "s@{{ elasticsearch_hosts }}@${elasticsearch_hosts_array}@" "${IN_FILE}" >"${OUT_FILE}"
fi

if [ "${ELASTICSEARCH_TAGS}" != "" ] && [ "${ELASTICSEARCH_TAGS}" != "null" ]; then
    # Covert string into comma separated array
    elasticsearch_tags_array=$(for tag in ${ELASTICSEARCH_TAGS}; do echo -n "\"${tag}\", "; done | sed -E "s@, \$@@g")
    sed -e "s@#{{ elasticsearch_tags }}@tags: [${elasticsearch_tags_array}]@" -i "${OUT_FILE}"
fi
