#!/usr/bin/env bash

set -eEuo pipefail

function cleanup() {
    echo "* clean temporary directory"
    rm -rf "$TMP_DIR"
}

TMP_DIR=$(mktemp -d)
trap cleanup EXIT SIGHUP SIGINT SIGQUIT SIGABRT
UNTAR_DIR="$TMP_DIR/tmp_rootfs"
TAR_FILE=""

if [ $# -eq 1 ]; then
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo "Meant to be used alongside bazel - can be used with and whithout arguments"
        echo "$ bazel run //ic-os/boundary-guestos/envs/prod:vuln-scan -- <full path to desired output directory>"
        echo "$ bazel run //ic-os/guestos/prod:vuln-scan"
        exit 1
    else
        REPORT_OUTPUT="$1"
        echo "* output path has been set to $REPORT_OUTPUT"
    fi
else
    echo "- output path has not been set, will use bazel cache instead"
    REPORT_OUTPUT="report.html"
fi

# we could have selected the first element in the array, however here we do not
# make the assumption of which element in the list comes first and decided to
# check
echo "* select the correct docker tar"
for f in $DOCKER_TAR; do
    if [ "${f: -4}" == ".tar" ]; then
        TAR_FILE=$f
        echo "+ TAR_FILE=$TAR_FILE"
        break
    fi
done

echo "* check that TAR_FILE has been found"
if [ -z "$TAR_FILE" ]; then
    echo >&2 "- could not find correct tar file"
    exit 1
fi

echo "* untar filesystem"
mkdir "$UNTAR_DIR"
tar -C "$UNTAR_DIR" -xf $(realpath "$TAR_FILE")

echo "* trivy scan"
"$trivy_path" rootfs --format template --template "@$TEMPLATE_FILE" \
    -o "$REPORT_OUTPUT" "$UNTAR_DIR"

echo "* path of report"
ls -lah $(realpath "$REPORT_OUTPUT")
