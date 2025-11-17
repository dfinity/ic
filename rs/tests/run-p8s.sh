#! /usr/bin/env nix-shell
#! nix-shell run-p8s.nix -i bash

# TODO: Rewrite this to use docker instead of Nix
# See: https://dfinity.atlassian.net/browse/VER-1941

set -euo pipefail

function usage() {
    cat <<EOF
Usage:
  run-p8s.sh [--prometheus-port PROMETHEUS_PORT] [--grafana-port GRAFANA_PORT] [--grafana-dashboards-dir GRAFANA_DASHBOARDS_DIR] prometheus-data-dir.tar.zst

  Run a local prometheus and grafana on the data directory packaged in the specified tarball.

  Tip: you're most likely running this script on your devenv. So to make the Grafana Web UI accessible on your laptop
  use the following to forward its port to your devenv:

      ssh devenv -L 3000:localhost:3000 -N

  OPTIONS:

  --prometheus-port PROMETHEUS_PORT

    Let prometheus listen on port PROMETHEUS_PORT.
    Defaults to 9090.

  --grafana-port GRAFANA_PORT

    Let grafana listen on port GRAFANA_PORT.
    Defaults to 3000.

  --grafana-dashboards-dir GRAFANA_DASHBOARDS_DIR

    Provision Grafana dashboards from the specified GRAFANA_DASHBOARDS_DIR directory.

    Tip: point it to your local clone of the k8s repo. I.e.:

        --grafana-dashboards-dir ~/k8s/bases/apps/ic-dashboards/

  --help

    Displays this help message.
EOF
    exit
}

################################################################################
# Process inputs
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            shift
            usage
            ;;
        --prometheus-port)
            PROMETHEUS_PORT="$2"
            shift
            shift
            ;;
        --grafana-port)
            GRAFANA_PORT="$2"
            shift
            shift
            ;;
        --grafana-dashboards-dir)
            GRAFANA_DASHBOARDS_DIR="$2"
            shift
            ;;
        *)
            TARBALL="$1"
            shift
            ;;
    esac
done

PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"

info() { echo "$*"; }
warn() { info "$*" 1>&2; }
die() {
    warn "$*"
    exit 1
}

if [ -z "${TARBALL:-}" ]; then
    die "Please specify the path to a prometheus-data-dir.tar.zst tarball"
fi

################################################################################
# Launch prometheus
################################################################################

prometheus_data_dir="$(mktemp -d -t prometheus-data-dir.XXXX)"

info "Unpacking $TARBALL to $prometheus_data_dir ..."
tar -xvf "$TARBALL" -C "$prometheus_data_dir"

cat <<EOF >"$prometheus_data_dir"/prometheus.yml
{
}
EOF

info "Running prometheus on the unpacked data directory ..."
cd "$prometheus_data_dir"

cleanup() {
    pkill -P $$
}

trap cleanup EXIT

prometheus \
    --storage.tsdb.path="$prometheus_data_dir" \
    --config.file="$prometheus_data_dir"/prometheus.yml \
    --web.listen-address=127.0.0.1:"$PROMETHEUS_PORT" &

################################################################################
# Launch grafana
################################################################################

grafana_data_dir="$(mktemp -d -t grafana-data-dir.XXXX)"
ln -fs "$GRAFANA/share/grafana/conf" "$grafana_data_dir"
ln -fs "$GRAFANA/share/grafana/tools" "$grafana_data_dir"
ln -fs "$GRAFANA/share/grafana/public" "$grafana_data_dir"

mkdir "$grafana_data_dir"/{datasources,plugins,notifiers,dashboards}
cat <<EOF >"$grafana_data_dir/datasources/datasource.yaml"
{
    "apiVersion": 1,
    "datasources": [
        {
            "name": "IC Metrics (cluster local)",
            "type": "prometheus",
            "uid": "000000001",
            "url": "http://127.0.0.1:$PROMETHEUS_PORT",
            "isDefault": true,
            "jsonData":
            {
              "httpMethod": "POST",
              "timeInterval": "10s"
            }
        }
    ]
}
EOF

if [ -n "${GRAFANA_DASHBOARDS_DIR:-}" ]; then
    provisioned_grafana_dashboards="$grafana_data_dir/dashboards/provisioned"
    cp -r "$GRAFANA_DASHBOARDS_DIR" "$provisioned_grafana_dashboards"
    cat <<EOF >"$grafana_data_dir/dashboards/dashboard.yaml"
{
    "apiVersion": 1,
    "providers": [
       {
         "name": "provisioned-grafana-dashboards",
         "options": {
           "path": "$provisioned_grafana_dashboards",
           "foldersFromFilesStructure": true
         }
       }
    ]
}
EOF

fi

cd "$grafana_data_dir"

export GF_PATHS_DATA="$grafana_data_dir"
export GF_PATHS_PROVISIONING="$grafana_data_dir"
export GF_PATHS_LOGS="$grafana_data_dir/log"
export GF_SERVER_PROTOCOL="http"
export GF_SERVER_HTTP_ADDR="127.0.0.1"
export GF_SERVER_HTTP_PORT="$GRAFANA_PORT"
export GF_SERVER_DOMAIN="localhost"
export GF_SERVER_STATIC_ROOT_PATH="$GRAFANA/share/grafana/public"
export GF_AUTH_ANONYMOUS_ENABLED="true"
export GF_AUTH_ANONYMOUS_ORG_NAME="Main Org."
export GF_AUTH_ANONYMOUS_ORG_ROLE="Admin"
export GF_AUTH_DISABLE_LOGIN_FORM="true"

grafana-server -homepath "$grafana_data_dir" &

wait $!
