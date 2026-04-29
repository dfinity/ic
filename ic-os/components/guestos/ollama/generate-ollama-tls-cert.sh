#!/bin/sh
# Generate a self-signed TLS certificate used by stunnel to terminate TLS in
# front of the local ollama backend.
#
# This runs as a systemd oneshot before stunnel starts. It is idempotent: if
# the cert + key already exist, it does nothing. Files are written to
# /var/lib/ollama-tls/, which lives on the writable /var partition (the
# rootfs is dm-verity read-only).
#
# The cert is intentionally untrusted / self-signed: clients are expected
# to use `curl -k`, `--insecure`, or to pin/import the generated cert
# out-of-band. There is no PKI involved here.

set -eu

CERT_DIR=/var/lib/ollama-tls
CERT_FILE="${CERT_DIR}/cert.pem"
KEY_FILE="${CERT_DIR}/key.pem"
COMBINED_FILE="${CERT_DIR}/stunnel.pem"

mkdir -p "${CERT_DIR}"
chmod 0750 "${CERT_DIR}"

if [ -s "${CERT_FILE}" ] && [ -s "${KEY_FILE}" ] && [ -s "${COMBINED_FILE}" ]; then
    echo "TLS material already present at ${CERT_DIR}, nothing to do." >&2
    exit 0
fi

# Resolve a stable Subject CN. We have no DNS at this layer; use the
# machine-id as a deterministic, non-secret identifier. Falls back to
# "ollama" if /etc/machine-id is somehow unavailable.
CN="ollama"
if [ -s /etc/machine-id ]; then
    CN="ollama-$(cat /etc/machine-id)"
fi

umask 077

# 10-year validity. The cert is untrusted by construction, so date validity
# is not security-relevant; we just want it long enough to outlive a
# realistic node lifetime without rotation.
openssl req \
    -x509 \
    -newkey rsa:2048 \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -days 3650 \
    -nodes \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1,IP:0.0.0.0" \
    >/dev/null 2>&1

# stunnel reads cert + key from a single PEM file when configured with
# `cert = ...` (no separate `key = ...`). Ship a combined file so the
# stunnel config stays trivial.
cat "${CERT_FILE}" "${KEY_FILE}" >"${COMBINED_FILE}"

# Owned by root; readable by the stunnel4 group. stunnel4 drops privileges
# to user `stunnel4` after reading its config + cert.
chown root:stunnel4 "${KEY_FILE}" "${CERT_FILE}" "${COMBINED_FILE}"
chmod 0640 "${KEY_FILE}" "${CERT_FILE}" "${COMBINED_FILE}"

echo "Generated self-signed TLS cert at ${CERT_FILE} for CN=${CN}." >&2
