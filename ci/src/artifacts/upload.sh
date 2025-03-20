#!/usr/bin/env bash

set -eEuo pipefail

# If $UPLOADABLES is set, then we call ourselves again with every file
# in $UPLOADABLES. This effectively avoids this whole file being one big
# for loop and keeps the indentation down.
if [ -n "${UPLOADABLES:-}" ]; then
    for uploadable in $UPLOADABLES; do
        echo found uploadable "$uploadable"
        abs_path="$BUILD_WORKING_DIRECTORY/$uploadable"
        env -u "UPLOADABLES" "$0" "$abs_path"
    done

    exit 0
fi

echo "uploading $1"

# ~/.aws/credentials is needed by rclone. If home is not set, expect
# VERSION_FILE to contain the $HOME.
if [ -z "${HOME:-}" ]; then
    while read -r k v; do
        case "$k" in
            HOME)
                export HOME="$v"
                ;;
        esac
    done <"$VERSION_FILE"
fi

VERSION="$(cat $VERSION_TXT)"

# rclone reads the $(dirname $f) to get file attributes.
# Therefore symlink should be resolved.
f="${1:?No file to upload}"
if [ -L "$f" ]; then
    f=$(readlink "$f")
fi

if [ "$(basename $f)" == "SHA256SUMS" ]; then
    echo "SHA256SUMS Content:" >&2
    cat "$f" >&2
fi

# Multipart upload does not work trough Cloudflare for some reason.
# Just disabling it with `--s3-upload-cutoff` for now.
rclone_common_flags=(
    --stats-one-line
    --checksum
    --immutable
    --s3-upload-cutoff=5G
)

REMOTE_SUBDIR="${REMOTE_SUBDIR:?Remote subdirectory not set}"

echo "uploading $f to AWS" >&2
AWS_PROFILE=default "$RCLONE" \
    "${rclone_common_flags[@]}" \
    --s3-provider=AWS \
    --s3-region=eu-central-1 \
    --s3-env-auth \
    copy \
    "$f" \
    ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
echo "done uploading to AWS" >&2

# Upload to Cloudflare's R2 (S3)
# using profile 'cf' to look up the right creds in ~/.aws/credentials
echo "uploading $f to Cloudflare" >&2
AWS_PROFILE=cf "$RCLONE" -v \
    "${rclone_common_flags[@]}" \
    --s3-provider=Cloudflare \
    --s3-endpoint=https://64059940cc95339fc7e5888f431876ee.r2.cloudflarestorage.com \
    --s3-env-auth \
    copy \
    "$f" \
    ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
echo "done uploading to Cloudflare" >&2

URL_PATH="ic/${VERSION}/$REMOTE_SUBDIR/$(basename $f)"
echo "https://download.dfinity.systems/${URL_PATH}" >&2
if [ -n "${2:-}" ]; then
    echo "https://download.dfinity.systems/${URL_PATH}" >"$2"
fi
