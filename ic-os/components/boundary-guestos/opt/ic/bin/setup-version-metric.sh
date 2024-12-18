#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source /opt/ic/bin/metrics.sh

readonly VERSION_METRIC="${BOOT_DIR}/buildinfo/version.prom"

cp ${VERSION_METRIC} "${METRICS_DIR}/version.prom"
