#!/usr/bin/env bash

set -x

DATE="$(date +%Y%m%d_%H%M%S)"
NNS_ENDPOINT_IP6="2a00:fb01:400:100:5000:ceff:fea2:bb0"
CURRENT_LOCATION="$(dirname -- "$0")"
IC_VERSION_ID="$("${CURRENT_LOCATION}/../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh" origin/master)"
curl -O "https://download.dfinity.systems/ic/${IC_VERSION_ID}/release/ic-regedit.gz"
gunzip -f ic-regedit.gz
chmod +x ic-regedit
./ic-regedit canister-snapshot --url "https://[${NNS_ENDPOINT_IP6}]:8080" >mercury-reg-snap.json
cp mercury-reg-snap.json "mercury-reg-snap--${DATE}.json"

set +x
