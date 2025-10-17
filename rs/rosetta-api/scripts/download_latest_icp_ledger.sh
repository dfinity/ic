#!/usr/bin/env bash
set -uo pipefail

### Configuration
RELEASE_TAG_PREFIX=ledger-suite-icp
# FIXME(FI-1845): Update to the new wasm file name after the next release
WASM_FILE=ledger-canister_notify-method.wasm.gz
DID_FILE=ledger.did

### Download a specific release
## Download the ICP ledger WASM and did files for a specific release. The files are downloaded
## from the github release page for the given release.
download_release() {
    RELEASE=$1
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L --head \
        "https://github.com/dfinity/ic/releases/download/${RELEASE}/${WASM_FILE}")
    if (($STATUS_CODE >= 200)) && (($STATUS_CODE < 300)); then
        echo "Found artifacts for release $RELEASE. Downloading ${DID_FILE} and ${WASM_FILE}"
        curl -sLf "https://github.com/dfinity/ic/releases/download/${RELEASE}/${DID_FILE}" \
            -o "${DID_FILE}"
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the ${DID_FILE} file. Please try again"
            exit 2
        fi
        curl -sLf "https://github.com/dfinity/ic/releases/download/${RELEASE}/${WASM_FILE}" \
            -o "${WASM_FILE}"
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the ${WASM_FILE} file. Please try again"
            exit 3
        fi
        exit 0
    fi
}

### Find and download the latest ICP ledger WASM and did file
## List the releases from the repository, looking for the most recent release where the corresponding
## tag starts with the expected prefix. Retrieves releases one page at a time, stopping if no release
## was found in some predefined maximum number of pages. Once a release is found, download the ledger
## WASM and did files.
find_and_download_release() {
    PAGE=1
    ITEMS_PER_PAGE=100
    MAX_PAGES=10
    while true; do
        ITEM=0
        # Unauthenticated requests are rate limited (per IP address) to 60 requests/hr
        # https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-unauthenticated-users
        REL_JSON=$(curl -L \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            https://api.github.com/repos/dfinity/ic/releases\?per_page\=${ITEMS_PER_PAGE}\&page\=${PAGE})
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to fetch the releases from dfinity/ic."
            exit 1
        fi
        while [ ${ITEM} -lt ${ITEMS_PER_PAGE} ]; do
            RELEASE=$(echo ${REL_JSON} | jq ".[${ITEM}].tag_name" | tr -d '"')
            if [ "$?" -ne "0" ]; then
                echo >&2 "Error parsing release from response."
                exit 1
            fi
            if [[ ${RELEASE} == ${RELEASE_TAG_PREFIX}* ]]; then
                download_release "${RELEASE}"
                break
            else
                ITEM=$((ITEM + 1))
            fi
        done
        PAGE=$((PAGE + 1))
        if [ ${PAGE} -gt ${MAX_PAGES} ]; then
            echo "No ${RELEASE_TAG_PREFIX} release found in the first ${MAX_PAGES} with ${ITEMS_PER_PAGE} items per page, aborting."
            exit 1
        fi
    done
}

find_and_download_release
