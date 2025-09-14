#!/usr/bin/env bash

set -eEuo pipefail

BUNDLE="${1:?No bundle to upload}"
DRY_RUN="${DRY_RUN:-}"

# Multipart upload does not work trough Cloudflare for some reason.
# Just disabling it with `--s3-upload-cutoff` for now.
rclone_common_flags=(
    --stats-one-line
    --checksum
    --s3-upload-cutoff=5G
    --s3-no-check-bucket
    --config /dev/null # don't use a config file
)

log() {
    echo "$@" >&2
}

log "VERSION: $VERSION"
log "rclone version: $("$RCLONE" --version)"

rclone() {
    if [[ $DRY_RUN == "1" ]]; then
        log "[rclone dry run]"
    else
        "$RCLONE" "$@"
    fi
}

upload() {
    artifact_localpath="$1"
    bucket_path="$2"
    bucket_dirname="$(dirname "$bucket_path")"

    log "uploading to '$bucket_path' ('$artifact_localpath' -> '$bucket_dirname')"
    log "uploading to AWS"

    # NOTE: we upload a "directory" and narrow down the upload with --files-from so that only
    # the current artifact is uploaded. Without this, --immutable does not work as expected.
    # https://github.com/rclone/rclone/issues/4921
    AWS_PROFILE=default rclone \
        "${rclone_common_flags[@]}" \
        --s3-provider=AWS \
        --s3-region=eu-central-1 \
        --s3-env-auth \
        copy \
        --files-from <(echo "$(basename "$artifact_localpath")") \
        --no-traverse \
        --immutable \
        "$(dirname "$artifact_localpath")" \
        ":s3:dfinity-download-public/$bucket_dirname"
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
        --files-from <(echo "$(basename "$artifact_localpath")") \
        --no-traverse \
        --immutable \
        "$(dirname "$artifact_localpath")" \
        ":s3:dfinity-download-public/$bucket_dirname"
    log "done uploading to Cloudflare"
}

# For each artifact in the bundle, extract the relative path to the bundle root and
# use that as the bucket path.
for fullrelpath in $(find -L "$BUNDLE" -type f); do
    artifact="${fullrelpath#$BUNDLE/}"
    artifact_basename="$(basename "$artifact")"
    artifact_subdir="$(dirname "$artifact")"

    if [[ $artifact_subdir == "." ]]; then
        # if dirname is '.', then the artifact is in the current dir and
        # we don't set a prefix
        artifact_prefix="ic/$VERSION"
    else
        artifact_prefix="ic/$VERSION/$artifact_subdir"
    fi

    bucket_path="$artifact_prefix/$artifact_basename"

    log
    log
    log "-- uploading '$artifact_basename' (remote path: '$bucket_path') --"

    # rclone reads the $(dirname $f) to get file attributes.
    # Therefore symlink should be resolved.
    artifact_fullpath="$(readlink -f "$fullrelpath")"
    upload "$artifact_fullpath" "$bucket_path"

    artifact_checksum="$(sha256sum "$artifact_fullpath" | cut -d' ' -f1)"
    echo "$artifact_checksum,https://download.dfinity.systems/$bucket_path"
done
