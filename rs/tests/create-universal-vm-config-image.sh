#!/usr/bin/env bash
set -eEou pipefail

usage() {
    cat <<EOF
Usage:
  $(basename $BASH_SOURCE) [--help] --input INPUT_DIR --output OUTPUT_FILE

  Creates a zstd-compressed image OUTPUT_FILE containing a FAT filesystem with the label "CONFIG" containing the contents of INPUT_DIR.

  This image can then be uploaded to the Farm service and attached to a universal VM. The universal VM will then mount the filesystem and execute the 'activate' script in the image.

  The 'activate' script can then do whatever is required but the expectation is that it will run a docker container, i.e.: 'docker run ... my-container'.

  --help

    Displays this help message.

  --input / -i

    The directory of which the contents is copied to the config image.

  --output / -o

    The output file to which to write the config image.

EOF

    exit
}

die() {
    echo "$1" 1>&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --help | -h)
            shift
            usage
            ;;
        --input | -i)
            INPUT_DIR="$2"
            shift
            shift
            ;;
        --output | -o)
            OUTPUT_FILE="$2"
            shift
            shift
            ;;
    esac
done

if [[ -z "${INPUT_DIR:-}" || -z "${OUTPUT_FILE:-}" ]]; then
    usage
fi

if [[ ! -x "$INPUT_DIR/activate" ]]; then
    die "No activate executable found in $INPUT_DIR!"
fi

tmp=$(mktemp)

finalize() {
    rm "$tmp"
}

trap finalize EXIT

truncate -s 1M "$tmp"
mkfs.vfat -n CONFIG "$tmp"
mcopy -i "$tmp" -o "$INPUT_DIR"/* ::
zstd -i "$tmp" -o "$OUTPUT_FILE"
