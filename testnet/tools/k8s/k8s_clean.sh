#!/usr/bin/env bash

if (($# < 1)); then
    echo "Usage: $0 <name>"
    echo "  <name>: TestNet name."
    exit 1
fi

kubectl -n "$NAMESPACE" delete --ignore-not-found=true vm ${1}-0 ${1}-1
kubectl -n "$NAMESPACE" delete --ignore-not-found=true dv ${1}-0-image ${1}-1-image
kubectl -n "$NAMESPACE" delete --ignore-not-found=true dv ${1}-0-config ${1}-1-config
kubectl -n "$NAMESPACE" delete --ignore-not-found=true pod ${1}-init
kubectl -n "$NAMESPACE" delete --ignore-not-found=true dv ${1}-init
kubectl -n "$NAMESPACE" delete --ignore-not-found=true ipreservation testnet-${1}
