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

# rclone reads the $(dirname $f) to get file attributes.
# Therefore symlink should be resolved.
f="$1"
if [ -L "$f" ]; then
    f=$(readlink "$f")
fi

if [ "$(basename $f)" == "SHA256SUMS" ]; then
    echo "SHA256SUMS Content:" >&2
    cat "$f" >&2
fi

# Multipart upload does not work trough the proxy or through Cloudflare for some
# reason. Just disabling it with `--s3-upload-cutoff` for now.
rclone_common_flags=(
        --stats-one-line \
        --checksum \
        --immutable \
        --s3-upload-cutoff=5G \
    )

if [ "${UPLOAD_BUILD_ARTIFACTS:-}" == "1" ]; then
    echo "uploading $f to cluster S3"
    "$RCLONE" \
        "${rclone_common_flags[@]}" \
        --s3-endpoint=https://s3-upload.idx.dfinity.network \
        copy \
        "$f" \
        ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"

    echo "uploading $f to AWS"
    AWS_PROFILE=default "$RCLONE" \
        "${rclone_common_flags[@]}" \
        --s3-provider=AWS \
        --s3-region=eu-central-1 \
        --s3-env-auth \
        copy \
        "$f" \
        ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"

    # Upload to Cloudflare's R2 (S3)
    # using profile 'cf' to look up the right creds in ~/.aws/credentials
    echo "uploading $f to Cloudflare"
    echo AWS_PROFILE=cf "$RCLONE" -v \
        "${rclone_common_flags[@]}" \
        --s3-provider=Cloudflare \
        --s3-endpoint=https://64059940cc95339fc7e5888f431876ee.r2.cloudflarestorage.com \
        --s3-env-auth \
        copy \
        "$f" \
        ":s3:dfinity-download-public/ic/${VERSION}/$REMOTE_SUBDIR/"
else
    echo "dry run for $f"
fi

URL_PATH="ic/${VERSION}/$REMOTE_SUBDIR/$(basename $f)"
echo "https://download.dfinity.systems/${URL_PATH}" >"$2"
