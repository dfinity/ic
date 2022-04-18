#!/bin/bash

set -e

for argument in "${@}"; do
    case ${argument} in
        -d | --debug)
            DEBUG=1
            ;;
        -h | --help)
            echo 'Usage:

Arguments:
  --upgrade-image=      Build the image to upgrade
  --out=                Output file name of the modified upgrade image
  --version=            Version number to use in the upgrade, defaults to 42
'
            exit 1
            ;;
        --upgrade-image=*)
            UPGRADE_IMAGE="${argument#*=}"
            shift
            ;;
        --out=*)
            OUT="${argument#*=}"
            shift
            ;;
        --version=*)
            VERSION="${argument#*=}"
            shift
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

echo "➡️  Preparing image to upgrade (version: $VERSION in: $UPGRADE_IMAGE out: $OUT)"
(
    D=$(mktemp -d)
    cd $D
    tar -tf $UPGRADE_IMAGE
    tar -xf $UPGRADE_IMAGE --sparse

    # Check current file number in image
    echo "cat /opt/ic/share/version.txt" | debugfs root.img -f -
    echo "${VERSION}" >version.txt
    cat <<EOF | debugfs root.img -w -f -
cd /opt/ic/share
rm version.txt
write version.txt version.txt
EOF
    echo "cat /opt/ic/share/version.txt" | debugfs root.img -f -
    cp version.txt VERSION.TXT
    cat version.txt
    tar -czf "$OUT" --sparse .

    tar -tf "$OUT"
    ls -anh "$OUT"

    rm -rf "$D"
)

exit 0
