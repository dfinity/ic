#!/usr/bin/env bash

set -eo pipefail

source $(dirname "${BASH_SOURCE[0]}")/artifact-utils.sh

INPUT_FILE="$1"

version_from_disk_image "${INPUT_FILE}"
