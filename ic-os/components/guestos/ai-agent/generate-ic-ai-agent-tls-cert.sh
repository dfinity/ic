#!/bin/sh
# Generate a self-signed TLS certificate used by stunnel to terminate TLS in
# front of the local ic-ai-agent backend.
#
# Mirrors generate-ollama-tls-cert.sh in shape; idempotent oneshot.

set -eu

CERT_DIR=/var/lib/ic-ai-agent-tls
CERT_FILE="${CERT_DIR}/cert.pem"
KEY_FILE="${CERT_DIR}/key.pem"
COMBINED_FILE="${CERT_DIR}/stunnel.pem"

mkdir -p "${CERT_DIR}"
chmod 0750 "${CERT_DIR}"

if [ -s "${CERT_FILE}" ] && [ -s "${KEY_FILE}" ] && [ -s "${COMBINED_FILE}" ]; then
    echo "TLS material already present at ${CERT_DIR}, nothing to do." >&2
    exit 0
fi

# Stable Subject CN derived from the machine-id.
CN="ic-ai-agent"
if [ -s /etc/machine-id ]; then
    CN="ic-ai-agent-$(cat /etc/machine-id)"
fi

umask 077

if ! openssl req \
    -x509 \
    -newkey rsa:2048 \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -days 3650 \
    -nodes \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1,IP:0.0.0.0" \
    2>/tmp/openssl-stderr.$$; then
    echo "openssl req failed:" >&2
    cat /tmp/openssl-stderr.$$ >&2 || true
    rm -f /tmp/openssl-stderr.$$
    exit 1
fi
rm -f /tmp/openssl-stderr.$$

cat "${CERT_FILE}" "${KEY_FILE}" >"${COMBINED_FILE}"

TARGET_GROUP="root"
if getent group stunnel4 >/dev/null 2>&1; then
    TARGET_GROUP="stunnel4"
fi
chown "root:${TARGET_GROUP}" "${KEY_FILE}" "${CERT_FILE}" "${COMBINED_FILE}"
chmod 0640 "${KEY_FILE}" "${CERT_FILE}" "${COMBINED_FILE}"

echo "Generated self-signed TLS cert at ${CERT_FILE} for CN=${CN} (group=${TARGET_GROUP})." >&2
