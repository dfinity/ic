#!/bin/bash

CONFIG_FILE="config.json5"
BACKUP_EXE="ic-backup"
BACKUP_EXE_GZ="${BACKUP_EXE}.gz"

function get_config_version() {
    CURRENT_VERSION=$(cat ${CONFIG_FILE} | jq '.version')
    echo "${CURRENT_VERSION}"
}

function set_config_version() {
    NEW_VERSION=$1
    JSON=$(jq ".version = ${NEW_VERSION}" ${CONFIG_FILE})
    echo ${JSON} | jq >${CONFIG_FILE}
}

function download_backup_binary() {
    BUILD_ID=$1
    DOWNLOAD_URL="https://download.dfinity.systems/ic/${BUILD_ID}/release/${BACKUP_EXE_GZ}"
    echo "Downloading: ${DOWNLOAD_URL} to ${BACKUP_EXE_GZ}"
    curl -L ${DOWNLOAD_URL} --output ${BACKUP_EXE_GZ}
    if [ -f "${BACKUP_EXE_GZ}" ]; then
        rm -f ${BACKUP_EXE}
        gunzip ${BACKUP_EXE_GZ}
        chmod +x ${BACKUP_EXE}
    else
        echo "Error downloading the file ${BACKUP_EXE_GZ} with build id ${BUILD_ID}"
        exit 1
    fi
}

# start of the main functionality
sudo systemctl stop ic-backup.service

VERSION=$(get_config_version)

if ((${VERSION} < 9)); then
    rm -f backup/backup_manager_state.json5
    set_config_version 9
fi
if ((${VERSION} < 10)); then
    download_backup_binary "d830848a6e9d6dd7f5ada9cdf6fcdbec6cf6b76b"
    ./ic-backup --config-file config.json5 upgrade
    set_config_version 10
fi
if ((${VERSION} < 11)); then
    download_backup_binary "d830848a6e9d6dd7f5ada9cdf6fcdbec6cf6b76b"
    set_config_version 11
fi

sudo systemctl start ic-backup.service
