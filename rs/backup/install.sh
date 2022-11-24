#!/bin/bash
#
# the latest copy of this file can be downloaded from:
#    https://raw.githubusercontent.com/dfinity/ic/master/rs/backup/install.sh
# running the installation:
#    bash <(curl -L https://raw.githubusercontent.com/dfinity/ic/master/rs/backup/install.sh)
#
# required binaries on the backup pod: bash, curl, gunzip
#

BACKUP_EXE="ic-backup"
BACKUP_EXE_GZ="${BACKUP_EXE}.gz"
CONFIG_FILE="config.json5"
SERVICE_CONFIG_FILE="ic-backup.service"
NNS_URL="https://ic0.app"
INSTALL_DIR="/usr/local/bin"
PUBLIC_KEY_FILE="ic_public_key.pem"
NODES_SYNCING=5
SYNCING_PERIOD=3600 # 1 hour
REPLAY_PERIOD=28800 # 8 hours
BACKUP_INSTANCE=$(hostname -a)

DEFAULT_BUILD_ID="ac1accd492dc689586245477eee4c97057b0e46a"
echo "Please enter the BUILD_ID of the proper ic-backup version:"
echo "(default: ${DEFAULT_BUILD_ID}):"
read BUILD_ID
if [ -z "${BUILD_ID// /}" ]; then
    BUILD_ID=${DEFAULT_BUILD_ID}
fi

DEFAULT_USER_ID="backup"
echo "Please enter backup process USER_ID"
echo "(default: ${DEFAULT_USER_ID}):"
read USER_ID
if [ -z "${USER_ID// /}" ]; then
    USER_ID=${DEFAULT_USER_ID}
fi

BACKUP_HOME=$(grep ${USER_ID} /etc/passwd | cut -d ":" -f6)

DEFAULT_WORK_DIR="${BACKUP_HOME}/backup-main"
echo "Please enter backup work directory"
echo "(default: ${DEFAULT_WORK_DIR}):"
read WORK_DIR
if [ -z "${WORK_DIR// /}" ]; then
    WORK_DIR=${DEFAULT_WORK_DIR}
fi

echo
echo
echo "BUILD_ID: '${BUILD_ID}'"
echo "WORK_DIR: '${WORK_DIR}'"
echo
echo

ROOT_DIR="${WORK_DIR}/backup"

rm -rf ${BACKUP_EXE} ${BACKUP_EXE_GZ}

DOWNLOAD_URL="https://download.dfinity.systems/ic/${BUILD_ID}/release/${BACKUP_EXE_GZ}"
echo "Downloading: ${DOWNLOAD_URL}"
curl -L ${DOWNLOAD_URL} --output ${BACKUP_EXE_GZ}

gunzip ${BACKUP_EXE_GZ}
chmod +x ${BACKUP_EXE}

read -r -d '' CONFIG <<-EOM
{
    "backup_instance":"${BACKUP_INSTANCE}",
    "nns_url":"${NNS_URL}",
    "nns_pem":"${WORK_DIR}/$PUBLIC_KEY_FILE",
    "root_dir":"${ROOT_DIR}",
    "excluded_dirs": ["backups", "diverged_checkpoints", "diverged_state_markers", "fs_tmp", "tip", "tmp" ],
    "ssh_private_key":"${BACKUP_HOME}/.ssh/id_ed25519_backup",
    "slack_token":"<INSERT SLACK TOKEN>",
    "subnets":
    [
        {
            "subnet_id":"<INSERT 1. SUBNET_ID>",
            "initial_replica_version": "<INSERT REPLICA_VERSION>",
            "nodes_syncing": ${NODES_SYNCING},
            "sync_period_secs":${SYNCING_PERIOD},
            "replay_period_secs":${REPLAY_PERIOD}
        },
        {
            "subnet_id":"<INSERT 2. SUBNET_ID>",
            "initial_replica_version": "<INSERT REPLICA_VERSION>",
            "nodes_syncing": ${NODES_SYNCING},
            "sync_period_secs":${SYNCING_PERIOD},
            "replay_period_secs":${REPLAY_PERIOD}
        }
    ]
}
EOM

echo "${CONFIG}" >${CONFIG_FILE}

PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9
gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bW
W5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg==
-----END PUBLIC KEY-----"

echo "${PUBLIC_KEY}" >${PUBLIC_KEY_FILE}

SERVICE_CONFIG="
[Unit]
Description=IC backup
After=systemd-networkd.service

[Service]
Type=simple
User=${USER_ID}
Environment=RUST_MIN_STACK=8192000
WorkingDirectory=${WORK_DIR}
ExecStart=${WORK_DIR}/ic-backup --config-file ${WORK_DIR}/config.json5
Restart=always

[Install]
WantedBy=multi-user.target
"

echo "${SERVICE_CONFIG}" >${SERVICE_CONFIG_FILE}

mkdir -p ${WORK_DIR}
mkdir -p ${ROOT_DIR}
cp ${BACKUP_EXE} ${WORK_DIR}
cp ${CONFIG_FILE} ${WORK_DIR}
cp ${PUBLIC_KEY_FILE} ${WORK_DIR}
sudo cp ${SERVICE_CONFIG_FILE} /etc/systemd/system
rm ${BACKUP_EXE} ${CONFIG_FILE} ${PUBLIC_KEY_FILE} ${SERVICE_CONFIG_FILE}

echo
echo
echo
echo "Please edit the config file ${CONFIG_FILE} placed in ${WORK_DIR}"
echo
echo "then start the backup service with:"
echo "sudo systemctl start ic-backup.service"
echo
echo "also consider to let it run on reboot with:"
echo "sudo systemctl enable ic-backup.service"
