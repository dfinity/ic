#!/usr/bin/env bash

set -eEuo pipefail

BASE_URL_DIRECT='https://artifacts.idx.dfinity.network'
BASE_URL_PROXY='https://artifacts.cache.idx.dfinity.network'

SHASUM="$(cat "${SHASUMFILE}")"

DIRECT_URL="${BASE_URL_DIRECT}/cas/${SHASUM}"

while ! curl --head --fail -L "${DIRECT_URL}"; do
    sleep 5
done

echo -n "${BASE_URL_PROXY}/cas/${SHASUM}" >"${OUT}"
