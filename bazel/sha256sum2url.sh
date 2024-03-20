#!/usr/bin/env bash

set -eEuo pipefail

BASE_URL_DIRECT='https://artifacts.idx.dfinity.network'
BASE_URL_PROXY='http://artifacts.idx.proxy-global.dfinity.network:8080'

SHASUM="$(cat "${SHASUMFILE}")"

DIRECT_URL="${BASE_URL_DIRECT}/cas/${SHASUM}"

echo "Attempting to download from URL ${DIRECT_URL}"
while ! curl --head --fail -L "${DIRECT_URL}"; do
    sleep 5
done

echo -n "${BASE_URL_PROXY}/cas/${SHASUM}" >"${OUT}"
