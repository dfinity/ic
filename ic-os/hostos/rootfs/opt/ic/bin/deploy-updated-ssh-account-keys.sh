#!/bin/bash

set -e

# Update configured ssh keys for the role accounts if a newer version
# is available.

# Only update readonly and backup keys.
for ACCOUNT in backup readonly; do
    echo "Checking authorized keys for ${ACCOUNT}"
    ORIGIN="/opt/ic/share/authorized_keys/${ACCOUNT}"
    if [ ! -r "${ORIGIN}" ]; then
        continue
    fi
    TARGET="/boot/config/hostos_accounts_ssh_authorized_keys/${ACCOUNT}"
    if [ ! -r "${TARGET}" ]; then
        echo "${ORIGIN} keys exist, but no ${TARGET} keys are present, skipping"
        continue
    fi
    ORIGIN_ENV=$(head -n 1 $ORIGIN)
    TARGET_ENV=$(head -n 1 $TARGET)
    if [ "${TARGET_ENV:0:1}" != "#" ]; then
        echo "Authorized keys for ${ACCOUNT} have no environment header, updating"
        cp "${ORIGIN}" "${TARGET}"
    elif [ "${TARGET_ENV}" = "${ORIGIN_ENV}" ]; then
        # Target's environment matches, check which is newer.
        ORIGIN_TIME=$(head -n 2 $ORIGIN | tail -n 1 | cut -c 3- | date -f - +%s)
        TARGET_TIME=$(head -n 2 $TARGET | tail -n 1 | cut -c 3- | date -f - +%s)
        if [ $ORIGIN_TIME -gt $TARGET_TIME ]; then
            echo "Authorized keys for ${ACCOUNT} are too old, updating: ${ORIGIN_TIME} vs ${TARGET_TIME}"
            cp "${ORIGIN}" "${TARGET}"
        fi
    else
        echo "The environments do not match, skipping: ${ORIGIN_ENV} vs ${TARGET_ENV}"
    fi
done
