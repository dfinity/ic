#!/bin/bash

function usage() {
    cat <<EOF
Usage:
  generate-btc-adapter-config -o ic-btc-adapter.json5

  Generate the bitcoin adapter config.

  -o outfile: output ic-btc-adapter.json5 file
EOF
}

while getopts "n:o:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

echo '{
    "network": "bitcoin"
}' >$OUT_FILE

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
