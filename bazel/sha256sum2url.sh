#!/usr/bin/env bash

set -eEuo pipefail

SHASUM="$(cat "${SHASUMFILE}")"

REDIRECT_URL="https://artifacts.idx.dfinity.network/cas/${SHASUM}"

echo "Waiting until ${REDIRECT_URL} is available ..."
while ! DIRECT_URL="$(curl --head --fail --silent "${REDIRECT_URL}" | grep "location: " | cut -d' ' -f2)"; do
    echo "${REDIRECT_URL} is not yet available, sleeping 5 seconds ..."
    sleep 5
done

# DIRECT_URL will now be set to something like:
#
#   https://artifacts.zh1-idx1.dfinity.network/cas/39579cf838a69258d8b4430512eb51026d05ff14416d08521783dc6664e3f0fc
#
# To form the correct URL to the dc_http_proxy we first need to extract the IDX k8s cluster like
# "zh1-idx1", "sf1-idx1" or "ln1-idx1".
CLUSTER=$(echo "${DIRECT_URL}" | cut -d. -f2)

DC_HTTP_PROXY_URL="http://${CLUSTER}.artifacts.proxy-global.dfinity.network:8080/cas/${SHASUM}"

echo "Using: ${DC_HTTP_PROXY_URL}"

echo -n "${DC_HTTP_PROXY_URL}" >"${OUT}"
