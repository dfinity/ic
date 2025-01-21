#!/usr/bin/env bash
set -uo pipefail

### Configuration
RELEASE_TAG_PREFIX=ledger-suite-icrc

### Download a specific release
##
download_release() {
    RELEASE=$1
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L --head \
        "https://github.com/dfinity/ic/releases/download/${RELEASE}/ic-icrc1-ledger.wasm.gz")
    if (($STATUS_CODE >= 200)) && (($STATUS_CODE < 300)); then
        echo "Found artifacts for release $RELEASE. Downloading icrc1_ledger.did and icrc1_ledger.wasm.gz"
        curl -sLf "https://github.com/dfinity/ic/releases/download/${RELEASE}/ledger.did" \
            -o icrc1_ledger.did
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the icrc1 ledger did file. Please try again"
            exit 2
        fi
        curl -sLf "https://github.com/dfinity/ic/releases/download/${RELEASE}/ic-icrc1-ledger.wasm.gz" \
            -o icrc1_ledger.wasm.gz
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the icrc1 ledger wasm file. Please try again"
            exit 3
        fi
        exit 0
    fi
}

### Find the previous release
## List the releases from the repository, looking for the most recent release where the corresponding
## tag starts with the expected prefix. Retrieves releases one page at a time, stopping if no release
## was found in some predefined maximum number of pages. Note that the calls to the github API for
## listing the releases are rate-limited unless authenticated.
find_and_download_release() {
    PREVIOUS_RELEASE=""
    PAGE=1
    ITEMS_PER_PAGE=100
    MAX_PAGES=10
    while [ "${PREVIOUS_RELEASE}" == "" ]; do
        ITEM=0
        # Unauthenticated requests are rate limited (per IP address) to 60 requests/hr
        # https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-unauthenticated-users
        REL_JSON=$(curl -L \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            https://api.github.com/repos/dfinity/ic/releases\?per_page\=${ITEMS_PER_PAGE}\&page\=${PAGE})
        while [ ${ITEM} -lt ${ITEMS_PER_PAGE} ]; do
            TAG=$(echo ${REL_JSON} | jq ".[${ITEM}].tag_name" | tr -d '"')
            if [[ ${TAG} == ${RELEASE_TAG_PREFIX}* ]]; then
                download_release "${TAG}"
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
echo "No commits with artifacts found"
exit 4
