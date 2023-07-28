#!/usr/bin/env bash

# Create K8s testnet VMs

set -eEuo pipefail

if (($# < 2)); then
    echo "Usage: $0 <name> <version>"
    echo "  <name>:    TestNet name."
    echo "  <version>: TestNet version (git revision)."
    echo "  <nns_size>: Number of NNS nodes to include in subnet."
    echo "  <app_size>: Number of APP nodes to include in subnet."
    exit 1
fi

export NAME=$1
export VERSION=$2
export NNS_SIZE=$3
export APP_SIZE=$4

if [ "${CIDR_RESERVATION:-}" == "" ]; then
    echo "CIDR_RESERVATION env var expected!" && exit 1
fi

if [ "${CIDR_PREFIX:-}" == "" ]; then
    echo "CIDR_PREFIX env var expected!" && exit 1
fi

if [ "${NAMESPACE:-}" == "" ]; then
    echo "NAMESPACE env var expected!" && exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUTDIR="$(dirname "$0")/out/${NAME}"
mkdir -p "$OUTDIR"

echo "Creating IPReservation"
envsubst <template-ipreservation.yaml >"$OUTDIR/ipreservation.yaml"
kubectl apply -f "$OUTDIR/ipreservation.yaml"

NNS_IPS=()
for ((i = 0; i < NNS_SIZE; i++)); do
    NNS_IPS+=("${CIDR_PREFIX}0${i}")
done

APP_IPS=()
for ((i = 0; i < APP_SIZE; i++)); do
    APP_IPS+=("${CIDR_PREFIX}1${i}")
done

IP_PREFIX="fda6:8d22:43e1::/48"
#########################################################################################
echo "Creating K8s config volumes..."
#########################################################################################

./k8s_config.sh "$VERSION" "${NNS_IPS[@]}" "${APP_IPS[@]}" "${IP_PREFIX}" "$OUTDIR"

NODE_INDEX=0
for ((i = 0; i < NNS_SIZE; i++)); do
    NODE_NAME="$NAME-${NODE_INDEX}"

    set -x
    virtctl -n "$NAMESPACE" image-upload dv "${NODE_NAME}-config" \
        --uploadproxy-url https://cdi-uploadproxy.sf1-idx1.dfinity.network \
        --image-path "$OUTDIR/bootstrap-$((NODE_INDEX++)).img" \
        --size=10Mi
    set +x
done

for ((i = 0; i < APP_SIZE; i++)); do
    NODE_NAME="$NAME-${NODE_INDEX}"

    set -x
    virtctl -n "$NAMESPACE" image-upload dv "${NODE_NAME}-config" \
        --uploadproxy-url https://cdi-uploadproxy.sf1-idx1.dfinity.network \
        --image-path "$OUTDIR/bootstrap-$((NODE_INDEX++)).img" \
        --size=10Mi
    set +x
done

#########################################################################################
echo "Creating K8s VMs..."
#########################################################################################

NODE_INDEX=0
for ((i = 0; i < NNS_SIZE; i++)); do
    export NODE_NAME="$NAME-$((NODE_INDEX++))"
    export IPV6="${NNS_IPS[$i]}"

    envsubst <template-vm.yaml >"$OUTDIR/$NODE_NAME.yaml"
    kubectl apply -f "$OUTDIR/$NODE_NAME.yaml"
done

for ((i = 0; i < APP_SIZE; i++)); do
    export NODE_NAME="$NAME-$((NODE_INDEX++))"
    export IPV6="${APP_IPS[$i]}"

    envsubst <template-vm.yaml >"$OUTDIR/$NODE_NAME.yaml"
    kubectl apply -f "$OUTDIR/$NODE_NAME.yaml"
done

#########################################################################################
echo "Doing ic-nns-init..."
#########################################################################################

pushd "$OUTDIR"

# Pack up registry state, canisters, and init binary
mkdir init

cp -r ic_registry_local_store init/

rclone --config="${REPO_ROOT}"/.rclone-anon.conf --include '*' copyto "public-s3:dfinity-download-public/ic/${VERSION}/canisters" "init/canisters"
find "init/canisters/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {}"

rclone --config="${REPO_ROOT}"/.rclone-anon.conf copy "public-s3:dfinity-download-public/ic/${VERSION}/release/ic-nns-init.gz" "init/"
gunzip -f "init/ic-nns-init.gz"
chmod +x "init/ic-nns-init"

tar -cf init.tar init

# Upload to init pod
set -x
virtctl -n "$NAMESPACE" image-upload dv "${NAME}-init" \
    --uploadproxy-url https://cdi-uploadproxy.sf1-idx1.dfinity.network \
    --archive-path ./init.tar --size=100Mi
set +x
popd

export NNS_IP="${NNS_IPS[0]}"
envsubst <template-init-job.yaml >"${OUTDIR}/${NAME}-init.yaml"
kubectl apply -f "${OUTDIR}/${NAME}-init.yaml"

echo "NNS Node IPs: ${NNS_IPS[@]}"
echo "APP Node IPs: ${APP_IPS[@]}"
