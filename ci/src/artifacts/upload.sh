#!/usr/bin/env bash

set -eEuo pipefail

while read -r k v; do
    case "$k" in
        HOME)
            # Required by rclone to get credentials from $HOME/.aws/credentials
            export HOME="$v"
            ;;
    esac
done <"$VERSION_FILE"

VERSION="$(cat $VERSION_TXT)"

# rclone reads the $(dirname $f) to get file attribuates.
# Therefore symlink should be resolved.
f="$1"
if [ -L "$f" ]; then
    f=$(readlink "$f")
fi

if [ "$(basename $f)" == "SHA256SUMS" ]; then
    echo "SHA256SUMS Content:" >&2
    cat "$f" >&2
fi

if [ "${UPLOAD_BUILD_ARTIFACTS:-}" == "1" ]; then
    echo "uploading $f"
    # Multipart upload does not work trough the proxy or through Cloudflare for some
    # reason. Just disabling it with `--s3-upload-cutoff` for now.
    "$RCLONE" \
        --config="$RCLONE_CONFIG" \
        --stats-one-line \
        --checksum \
        --immutable \
        --s3-upload-cutoff=5G \
        copy \
        "$f" \
        "public-s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"

    # Upload to Cloudflare's R2 (S3)
    unset RCLONE_S3_ENDPOINT
    AWS_PROFILE=cf "$RCLONE" \
        --config="$RCLONE_CONFIG" \
        --stats-one-line \
        --checksum \
        --immutable \
        --s3-upload-cutoff=5G \
        copy \
        "$f" \
        "public-s3-cf:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
else
    echo "dry run for $f"
fi

URL_PATH="ic/${VERSION}/$REMOTE_SUBDIR/$(basename $f)"
echo "https://download.dfinity.systems/${URL_PATH}" >"$2"
