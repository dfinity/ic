#!/usr/bin/env bash

set -eEuo pipefail

function log() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] $*"
}

function cleanup() {
    log "* clean temporary directory"
    rm -rf "$TMP_DIR"
}

function help() {
    echo "Usage: bazel run //ic-os/<image>:vuln-scan -- --format <html|json> --output-path <path to file> [--hash-output-path <path to file>] [--images <full path to ic repo>]"
    echo "  -f, --format: the output format 'html' or 'json'"
    echo "  -o, --output-path: full or relative path for output file"
    echo "  -h, --hash-output-path: full or relative path for file that contains sha256 hashes of rootfs binary files"
    echo "  --images: list the target for images"
    echo ""
    echo "Example:"
    echo "  bazel run //ic-os/boundary-guestos/envs/prod:vuln-scan -- --output-path guestos.html --format html --hash-output-path guestos.hash-list"
    echo "  bazel run //ic-os/boundary-guestos/envs/prod:vuln-scan -- --images $(pwd)"
    exit 1
}

function setup() {
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -f | --format)
                FORMAT="${2:-}"
                if ! [[ "$FORMAT" == "json" || "$FORMAT" == "html" ]]; then
                    log >&2 "- $FORMAT is an incorrect format"
                    help
                fi
                log " * format has been set to $FORMAT"
                shift
                ;;
            -o | --output-path)
                REPORT_OUTPUT="${2:-}"
                log " * output path has been set to $REPORT_OUTPUT"
                shift
                ;;
            -h | --hash-output-path)
                HASH_OUTPUT="${2:-}"
                log " * hash output path has been set to $HASH_OUTPUT"
                shift
                ;;
            --images)
                IMAGES="${2:-}"

                if [[ -d "$IMAGES" ]]; then
                    log " * available images:"
                    grep -Rl icos_build "$IMAGES/ic-os" | grep BUILD.bazel | xargs \
                        dirname | sort | sed 's/.*\(ic\/\)/\1/g'
                else
                    log >&2 " - $IMAGES is not a valid directory"
                fi

                exit 1
                ;;
            -?*) help ;;
            *)
                echo "${2:-}"
                help
                ;;
        esac
        shift
    done

    if [[ -z "${FORMAT:-}" ]]; then
        log 'missing -f, --format' >&2
        help
    fi

    if [[ -z "${REPORT_OUTPUT:-}" ]]; then
        log 'missing -o, --output-path' >&2
        help
    fi
}

function execution() {
    TMP_DIR=$(mktemp -d)
    trap cleanup EXIT SIGHUP SIGINT SIGQUIT SIGABRT
    UNTAR_DIR="$TMP_DIR/tmp_rootfs"
    TAR_FILE=""

    # we could have selected the first element in the array, however here we do not
    # make the assumption of which element in the list comes first and decided to
    # check
    log " * select the correct docker tar"
    for f in $CONTAINER_TAR; do
        if [ "${f: -4}" == ".tar" ]; then
            TAR_FILE=$f
            log " + TAR_FILE=$TAR_FILE"
            break
        fi
    done

    log " * check that TAR_FILE has been found"
    if [ -z "$TAR_FILE" ]; then
        log >&2 "- could not find correct tar file"
        exit 1
    fi

    log " * untar filesystem"
    mkdir "$UNTAR_DIR"
    tar -C "$UNTAR_DIR" -xf $(realpath "$TAR_FILE")

    log "* trivy scan"
    if [[ "$FORMAT" == "html" ]]; then
        "$trivy_path" rootfs --format template --template "@$TEMPLATE_FILE" \
            -o "$REPORT_OUTPUT" "$UNTAR_DIR"
    else
        "$trivy_path" rootfs -f "$FORMAT" -o "$REPORT_OUTPUT" "$UNTAR_DIR"
    fi

    log " * path of report"
    ls -lah $(realpath "$REPORT_OUTPUT")

    if [ -n "${HASH_OUTPUT:-}" ]; then
        log "* computing sha256 hashes of binary files"
        find "$UNTAR_DIR" -type f -executable -exec sha256sum {} \; >"$HASH_OUTPUT"

        log " * path of hash list"
        ls -lah $(realpath "$HASH_OUTPUT")
    fi
}

setup "$@"
execution
