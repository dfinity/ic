#!/bin/bash

METRICS_DIR="/run/node_exporter/collector_textfile"

# Writes a metric (including headers) with label to its own file (and overwriting
# that file on every call).
# Arguments:
#   $1: Metric name
#   $2: Labels (e.g., '{unit="foo"}')
#   $3: Metric value
#   $4: Help text
#   $5: Metric type (e.g., gauge, counter)
write_metric_attr() {
    local name=$1
    local attr=$2
    local value=$3
    local help=$4
    local type=$5

    echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name}${attr} ${value}" >"${METRICS_DIR}/${name}.prom"
}

# Writes a metric (including headers) to its own file (and overwriting that file on every call).
# Arguments:
#   $1: Metric name
#   $2: Metric value
#   $3: Help text
#   $4: Metric type (e.g., gauge, counter)
write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

# Writes metric headers (# HELP and # TYPE) to the file of the given metrics family.
# It is the caller's responsibility to ensure that headers are not duplicated and
# that the file is cleared when necessary.
# Arguments:
#   $1: Metrics family
#   $2: Metric name
#   $3: Help text
#   $4: Metric type (e.g., gauge, counter)
write_metric_header() {
    local metrics_family="$1"
    local name="$2"
    local help="$3"
    local type="$4"

    echo "# HELP ${name} ${help}" >>"${METRICS_DIR}/${metrics_family}.prom"
    echo "# TYPE ${name} ${type}" >>"${METRICS_DIR}/${metrics_family}.prom"
}

# Appends a metric value (with optional labels) to the file of the given metrics family.
# It is the caller's responsibility to ensure that the corresponding headers are
# present (i.e., by calling write_metric_header) and that the file is cleared
# when necessary (i.e., by calling clear_metrics).
# Arguments:
#   $1: Metrics family
#   $2: Metric name
#   $3: Labels (e.g., '{unit="foo"}') or an empty string for no labels.
#   $4: Metric value
append_metric() {
    local metrics_family="$1"
    local name="$2"
    local labels="$3"
    local value="$4"

    echo "${name}${labels} ${value}" >>"${METRICS_DIR}/${metrics_family}.prom"
}

# Clears the file fo the given metrics family.
# Arguments:
#   $1: Metrics family
clear_metrics() {
    local metrics_family="$1"

    >"${METRICS_DIR}/${metrics_family}.prom"
}
