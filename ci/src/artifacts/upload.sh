#!/usr/bin/env bash

set -eEuo pipefail

BUNDLE="${1:?No bundle to upload}"
DRY_RUN="${DRY_RUN:-}"

echo "VERSION: $VERSION"
echo "rclone version:"
"$RCLONE" --version

# Multipart upload does not work trough Cloudflare for some reason.
# Just disabling it with `--s3-upload-cutoff` for now.
rclone_common_flags=(
    --stats-one-line
    --checksum
    --immutable
    --s3-upload-cutoff=5G
    --s3-no-check-bucket
)

log() {
    echo "$@" >&2
}

rclone() {
    if [[ $DRY_RUN == "1" ]]; then
        log "[rclone dry run]"
    else
        "$RCLONE" "$@"
    fi
}

upload() {
    log "uploading to AWS"
    AWS_PROFILE=default rclone \
        "${rclone_common_flags[@]}" \
        --s3-provider=AWS \
        --s3-region=eu-central-1 \
        --s3-env-auth \
        copy \
        "$1" \
        ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
    log "done uploading to AWS"

    # Upload to Cloudflare's R2 (S3)
    # using profile 'cf' to look up the right creds in ~/.aws/credentials
    log "uploading to Cloudflare"
    AWS_PROFILE=cf rclone -v \
        "${rclone_common_flags[@]}" \
        --s3-provider=Cloudflare \
        --s3-endpoint=https://64059940cc95339fc7e5888f431876ee.r2.cloudflarestorage.com \
        --s3-env-auth \
        copy \
        "$1" \
        ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
    log "done uploading to Cloudflare"
}

# For each artifact in the bundle, extract the relative path to the bundle root and
# use that as the bucket path.
for fullrelpath in $(find -L "$BUNDLE" -type f); do
    artifact="${fullrelpath#$BUNDLE/}"
    artifact_basename="$(basename "$artifact")"
    artifact_subdir="$(dirname "$artifact")"
    log
    log
    log "-- uploading '$artifact_basename' (subdir: '$artifact_subdir') --"

    # rclone reads the $(dirname $f) to get file attributes.
    # Therefore symlink should be resolved.
    REMOTE_SUBDIR="$artifact_subdir" upload "$(readlink -f "$fullrelpath")"
    log "done uploading '$artifact_basename'"

    URL_PATH="ic/${VERSION}/$artifact_subdir/$artifact_basename"
    if [ -n "${2:-}" ]; then
        echo "https://download.dfinity.systems/${URL_PATH}" >>"$2"
    fi
done
