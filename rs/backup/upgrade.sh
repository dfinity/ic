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

if ((${VERSION} < 13)); then
    download_backup_binary "337e13c99e3ca4857c83aed203d5019407888dc9"
    ./ic-backup --config-file config.json5 upgrade
    set_config_version 13
fi
if ((${VERSION} < 16)); then
    download_backup_binary "5b43f5b35307460ecb0f75d5ab8a32e687a09a13"
    set_config_version 16
fi

sudo systemctl start ic-backup.service
