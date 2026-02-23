#!/bin/bash
set -e

# ─── Configuration ───
NNS_URL="${NNS_URL:-https://ic0.app}"
LOCAL_STORE_PATH="${LOCAL_STORE_PATH:-/data/ic_registry_local_store}"
NNS_PUB_KEY="${NNS_PUB_KEY:-/opt/ic/share/nns_public_key.pem}"
HTTP_PORT="${HTTP_PORT:-8080}"
HTTPS_PORT="${HTTPS_PORT:-443}"
METRICS_ADDR="${METRICS_ADDR:-0.0.0.0:9090}"
REPLICATOR_METRICS_ADDR="${REPLICATOR_METRICS_ADDR:-0.0.0.0:9092}"

# TLS configuration (pick ONE of these approaches):
#   Option A - ACME/Let's Encrypt: set TLS_HOSTNAME
#   Option B - Static certs:       set TLS_CERT_PATH and TLS_PKEY_PATH
#   Option C - HTTP only:          leave all TLS_* unset
TLS_HOSTNAME="${TLS_HOSTNAME:-}"
TLS_ACME_CREDENTIALS_PATH="${TLS_ACME_CREDENTIALS_PATH:-/data/acme}"
TLS_CERT_PATH="${TLS_CERT_PATH:-}"
TLS_PKEY_PATH="${TLS_PKEY_PATH:-}"

SKIP_REPLICA_TLS_VERIFICATION="${SKIP_REPLICA_TLS_VERIFICATION:-true}"

# How long to wait for registry bootstrap (seconds)
BOOTSTRAP_TIMEOUT="${BOOTSTRAP_TIMEOUT:-300}"

# ─── Banner ───
echo "============================================"
echo "  API Boundary Node (Disaster Recovery)"
echo "============================================"
echo "NNS URL:        ${NNS_URL}"
echo "Local Store:    ${LOCAL_STORE_PATH}"
echo "HTTP Port:      ${HTTP_PORT}"
if [ -n "${TLS_HOSTNAME}" ]; then
    echo "HTTPS Port:     ${HTTPS_PORT}"
    echo "TLS Mode:       ACME (Let's Encrypt) for ${TLS_HOSTNAME}"
elif [ -n "${TLS_CERT_PATH}" ] && [ -n "${TLS_PKEY_PATH}" ]; then
    echo "HTTPS Port:     ${HTTPS_PORT}"
    echo "TLS Mode:       Static certificates"
else
    echo "TLS Mode:       DISABLED (HTTP only)"
fi
echo "============================================"

# ─── Signal handling for graceful shutdown ───
REPLICATOR_PID=""
BOUNDARY_PID=""

cleanup() {
    echo ""
    echo "Shutting down..."
    [ -n "$BOUNDARY_PID" ] && kill "$BOUNDARY_PID" 2>/dev/null || true
    [ -n "$REPLICATOR_PID" ] && kill "$REPLICATOR_PID" 2>/dev/null || true
    wait
    echo "Shutdown complete."
}
trap 'cleanup; exit 0' SIGTERM SIGINT

# ─── Start registry replicator ───
echo "[1/3] Starting registry replicator..."
/opt/ic/bin/ic-registry-replicator \
    --nns-pub-key-pem "${NNS_PUB_KEY}" \
    --nns-url "${NNS_URL}" \
    --local-store-path "${LOCAL_STORE_PATH}" \
    --metrics-listen-addr "${REPLICATOR_METRICS_ADDR}" \
    --log-as-text \
    &
REPLICATOR_PID=$!

# ─── Wait for registry to bootstrap ───
echo "[2/3] Waiting for registry to bootstrap (timeout: ${BOOTSTRAP_TIMEOUT}s)..."
WAITED=0
while true; do
    # Check that replicator is still alive
    if ! kill -0 "$REPLICATOR_PID" 2>/dev/null; then
        echo "ERROR: Registry replicator exited unexpectedly."
        wait "$REPLICATOR_PID" || true
        exit 1
    fi

    # Check if local store has been populated
    if [ -d "${LOCAL_STORE_PATH}" ] && [ -n "$(ls -A "${LOCAL_STORE_PATH}" 2>/dev/null)" ]; then
        echo "Registry bootstrapped after ${WAITED}s."
        break
    fi

    if [ "$WAITED" -ge "$BOOTSTRAP_TIMEOUT" ]; then
        echo "ERROR: Registry failed to bootstrap within ${BOOTSTRAP_TIMEOUT}s."
        cleanup
        exit 1
    fi

    sleep 2
    WAITED=$((WAITED + 2))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "  Still waiting for registry data... (${WAITED}s)"
    fi
done

# ─── Build ic-boundary arguments ───
BOUNDARY_ARGS=(
    --registry-local-store-path "${LOCAL_STORE_PATH}"
    --listen-http-port "${HTTP_PORT}"
    --obs-log-stdout
    --obs-metrics-addr "${METRICS_ADDR}"
)

# TLS arguments
if [ -n "${TLS_HOSTNAME}" ]; then
    BOUNDARY_ARGS+=(
        --listen-https-port "${HTTPS_PORT}"
        --tls-hostname "${TLS_HOSTNAME}"
        --tls-acme-credentials-path "${TLS_ACME_CREDENTIALS_PATH}"
    )
elif [ -n "${TLS_CERT_PATH}" ] && [ -n "${TLS_PKEY_PATH}" ]; then
    BOUNDARY_ARGS+=(
        --listen-https-port "${HTTPS_PORT}"
        --tls-cert-path "${TLS_CERT_PATH}"
        --tls-pkey-path "${TLS_PKEY_PATH}"
    )
fi

if [ "${SKIP_REPLICA_TLS_VERIFICATION}" = "true" ]; then
    BOUNDARY_ARGS+=(--skip-replica-tls-verification)
fi

# Pass through any extra arguments from CMD
if [ $# -gt 0 ]; then
    BOUNDARY_ARGS+=("$@")
fi

# ─── Start ic-boundary ───
echo "[3/3] Starting ic-boundary..."
/opt/ic/bin/ic-boundary "${BOUNDARY_ARGS[@]}" &
BOUNDARY_PID=$!

echo ""
echo "API Boundary Node is running."
echo "  ic-boundary PID:          ${BOUNDARY_PID}"
echo "  registry-replicator PID:  ${REPLICATOR_PID}"
echo ""

# ─── Wait for either process to exit ───
wait -n "$REPLICATOR_PID" "$BOUNDARY_PID"
EXIT_CODE=$?

echo "A process exited with code ${EXIT_CODE}. Shutting down..."
cleanup
exit "$EXIT_CODE"
