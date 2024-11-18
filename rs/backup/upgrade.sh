#!/bin/bash

set -e

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
ENDCOLOR="\e[0m"

CONFIG_FILE="config.json5"

function download_backup_binary() {
    BUILD_ID=$1
    DOWNLOAD_URL="https://download.dfinity.systems/ic/${BUILD_ID}/release/ic-backup.gz"

    BACKUP_EXE="ic-backup_${BUILD_ID}"
    BACKUP_EXE_GZ="${BACKUP_EXE}.gz"

    echo -e "${YELLOW}Downloading: ${DOWNLOAD_URL} to ${BACKUP_EXE_GZ}${ENDCOLOR}"
    curl -L ${DOWNLOAD_URL} --output ${BACKUP_EXE_GZ} --fail
    if [ -f "${BACKUP_EXE_GZ}" ]; then
        gunzip ${BACKUP_EXE_GZ}
        chmod +x ${BACKUP_EXE}
    else
        echo -e "${RED}Error downloading the file ${BACKUP_EXE_GZ} with build id ${BUILD_ID}${ENDCOLOR}"
        exit 1
    fi

    echo -e "${GREEN}Successfully downloaded and unpacked the 'ic-backup' binary${ENDCOLOR}"
}

echo -e "${YELLOW}Attempting to upgrade the 'ic-backup' binary${ENDCOLOR}."

if [ -z "$1" ]; then
    echo -e "${YELLOW}Please provide a GIT SHA of the revision which contains the desired 'ic-backup' version. ${RED}Note ${YELLOW}that the revision should have a disk images built already.${ENDCOLOR}"
    echo -e "${YELLOW}To get the latest revision that has a disk image pre-built, you can run '${GREEN}ci/src/artifacts/newest_sha_with_disk_image.sh master${YELLOW}' from within the IC repo${ENDCOLOR}."

    read -p "GIT SHA: " git_sha
else
    git_sha=$1
fi

download_backup_binary ${git_sha}

echo -e "${YELLOW}Stopping the 'ic-backup' service${ENDCOLOR}."
sudo systemctl stop ic-backup.service

echo -e "${YELLOW}Creating a softlink 'ic-backup' -> 'ic-backup_${git_sha}'${ENDCOLOR}."
ln -s -f ic-backup_${git_sha} ic-backup

echo -e "${YELLOW}Starting the 'ic-backup' service${ENDCOLOR}."
sudo systemctl start ic-backup.service

echo -e "${GREEN}Successfully upgraded 'ic-backup' binary${ENDCOLOR}"
