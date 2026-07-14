#!/usr/bin/env bash
#
# Builds an SEV recovery GuestOS image.
#
# Usage:
#   bazel run //ic-os/guestos/envs/sev-recovery:build-sev-recovery -- \
#       --base=<guestos git commit> --proposal=<proposal id>
#
#   --base      git commit of the GuestOS release running on the node being
#               recovered. The matching GuestOS update image is downloaded here.
#   --proposal  id of the accepted BlessAlternativeGuestOsVersion proposal that
#               corresponds to the base version (its launch measurements must
#               match, which is checked at build time).

set -euo pipefail

# `bazel run` executes this script from inside its output tree; switch back to
# the workspace so the nested `bazel` invocations and relative paths work.
WORKSPACE="${BUILD_WORKING_DIRECTORY:?must be invoked via \`bazel run\`}"
cd "$WORKSPACE"

base_version=""
proposal_id=""
for arg in "$@"; do
    case "$arg" in
        --base=*)     base_version="${arg#--base=}" ;;
        --proposal=*) proposal_id="${arg#--proposal=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done

if [[ -z "$base_version" || -z "$proposal_id" ]]; then
    echo "usage: build-sev-recovery -- --base=<guestos git commit> --proposal=<proposal id>" >&2
    exit 1
fi

TARGET_PACKAGE="ic-os/guestos/envs/sev-recovery"
CBOR="$TARGET_PACKAGE/alternative_guestos_proposal.cbor"
IMG="$TARGET_PACKAGE/update-img-$base_version.tar.zst"
LINK="$TARGET_PACKAGE/base-update-img.tar.zst"
UPDATE_IMG_URL="https://download.dfinity.systems/ic/$base_version/guest-os/update-img/update-img.tar.zst"
TARGET="//$TARGET_PACKAGE:update-img.tar.zst"

echo "==> Downloading base GuestOS update image ($base_version)..."
# Cache by version in the filename (skip the download if already present), then
# point the fixed-name symlink — the build's input — at this version's image.
if [[ ! -f "$IMG" ]]; then
    curl --fail --silent --show-error --location "$UPDATE_IMG_URL" -o "$WORKSPACE/$IMG"
else
    echo "    $IMG already present, skipping download."
fi
ln -sfn "$(basename "$IMG")" "$WORKSPACE/$LINK"

echo "==> Downloading signed proposal ${proposal_id}..."
bazel run //rs/ic_os/build_tools/alternative_guestos -- download-signed-proposal \
    --proposal-id "$proposal_id" \
    --output "$WORKSPACE/$CBOR"

echo "==> Building SEV recovery image..."
bazel build "$TARGET"
