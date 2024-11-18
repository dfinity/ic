#!/bin/bash

METRICS_DIR="/run/node_exporter/collector_textfile"

write_metric_attr() {
    local name=$1
    local attr=$2
    local value=$3
    local help=$4
    local type=$5

    echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name}${attr} ${value}" >"${METRICS_DIR}/${name}.prom"
}

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}
