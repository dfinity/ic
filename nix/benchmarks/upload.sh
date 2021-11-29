#!/usr/bin/env bash
# vim ft: bash

set -euo pipefail

log() {
    echo "[benchmark-upload]" "$@"
}

err() {
    log "error:" "$@"
}

abort() {
    err "$@"
    exit 1
}

log "starting"

ok=true

if [ -n "${ELASTICSEARCH_URL:-}" ]; then
    log "ELASTICSEARCH_URL: $ELASTICSEARCH_URL"
else
    err "environment variable ELASTICSEARCH_URL not set" && ok=false
fi

if [ -n "${REPORTS:-}" ]; then
    log "REPORTS: $REPORTS"
else
    err "environment variable REPORTS not set" && ok=false
fi

if [ -d "$REPORTS/manifests" ]; then
    log "manifests directory exists"
else
    err "REPORTS ($REPORTS) does not have a manifests directory" && ok=false
fi

[ "$ok" == "true" ] || abort "Could not upload benchmark results."

curlArgs=(
    -H 'Content-Type: application/json'
    "$ELASTICSEARCH_URL?pretty"
)

for manifest in "$REPORTS/manifests"/*; do
    log "found manifest: $manifest"
    log "uploading to elasticsearch $ELASTICSEARCH_URL"
    log curl "${curlArgs[@]}" --data @"$manifest"
    curl "${curlArgs[@]}" --data @"$manifest"
done

log "done"
