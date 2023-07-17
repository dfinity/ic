#!/usr/bin/env bash

# Create K8s testnet VMs

set -eEuo pipefail

if (($# < 2)); then
    echo "Usage: $0 <name> <version>"
    echo "  <name>:    TestNet name."
    echo "  <version>: TestNet version (git revision)."
    exit 1
fi

export NAME=$1
export VERSION=$2
export SIZE=2

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

IPLIST=(
    "${CIDR_PREFIX}10"
    "${CIDR_PREFIX}11"
)

IP_PREFIX="fda6:8d22:43e1::/48"
#########################################################################################
echo "Creating K8s config volumes..."
#########################################################################################
#TODO: support k8s_config.sh with more then 2 nodes
./k8s_config.sh "$VERSION" "${IPLIST[0]}" "${IPLIST[1]}" "${IP_PREFIX}" "$OUTDIR"

for ((i = 0; i < SIZE; i++)); do
    export NODE_NAME="$NAME-$i"

    DIR="app"
    if [ "$i" == "0" ]; then
        DIR="nns"
    fi

    set -x
    virtctl -n "$NAMESPACE" image-upload dv "${NODE_NAME}-config" \
        --uploadproxy-url https://cdi-uploadproxy.sf1-idx1.dfinity.network \
        --image-path "$OUTDIR/$DIR/bootstrap.img" \
        --size=10Mi
    set +x
done

#########################################################################################
echo "Creating K8s VMs..."
#########################################################################################
for ((i = 0; i < SIZE; i++)); do
    export NODE_NAME="$NAME-$i"
    export IPV6="${IPLIST[$i]}"
    envsubst <template-vm.yaml >"$OUTDIR/$NODE_NAME.yaml"
    kubectl apply -f "$OUTDIR/$NODE_NAME.yaml"
done

#########################################################################################
echo "Doing ic-nns-init..."
#########################################################################################
pushd "$OUTDIR"
tar -cf init.tar init
set -x
virtctl -n "$NAMESPACE" image-upload dv "${NAME}-init" \
    --uploadproxy-url https://cdi-uploadproxy.sf1-idx1.dfinity.network \
    --archive-path ./init.tar --size=100Mi
set +x
popd

export NNS_IP="${IPLIST[0]}"
envsubst <template-init-job.yaml >"${OUTDIR}/${NAME}-init.yaml"
kubectl apply -f "${OUTDIR}/${NAME}-init.yaml"

echo "NNS Node IP: ${IPLIST[0]}"
echo "APP Node IP: ${IPLIST[1]}"
