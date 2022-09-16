#!/bin/bash

set -euox pipefail

readonly RUN_NODE_DIR='/run/ic-node'
readonly DBS_SRC_DIR='/boot/config/geolite2_dbs'
readonly DBS_DST_DIR='/etc/nginx/geoip'

err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function main() {
    if [[ ! -d "${DBS_SRC_DIR}" ]]; then
        err "missing geolite2 dbs dir: ${DBS_SRC_DIR}, defaulting to empty dbs"
        exit 0
    fi

    # Setup bind mount
    mkdir -p "${RUN_NODE_DIR}/${DBS_DST_DIR}"

    if [[ ! -d "${DBS_DST_DIR}" ]]; then
        mkdir -p "${DBS_DST_DIR}"
    fi

    mount --bind \
        "${RUN_NODE_DIR}/${DBS_DST_DIR}" \
        "${DBS_DST_DIR}"

    # Copy databases
    DB_NAMES=(
        GeoLite2-Country.mmdb
        GeoLite2-City.mmdb
    )

    for DB_NAME in "${DB_NAMES[@]}"; do
        if [[ ! -f "${DBS_SRC_DIR}/${DB_NAME}" ]]; then
            err "missing geolite2 db: ${DBS_SRC_DIR}/${DB_NAME}"
            exit 1
        fi

        cp \
            "${DBS_SRC_DIR}/${DB_NAME}" \
            "${RUN_NODE_DIR}/${DBS_DST_DIR}/${DB_NAME}"
    done
}

main "$@"
