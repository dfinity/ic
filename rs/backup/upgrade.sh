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

if ((${VERSION} < 26)); then
    download_backup_binary "6a917910ff4dc50b45e45a83c840091b51ef2a4f"
    set_config_version 26
fi

sudo systemctl start ic-backup.service
