#!/bin/sh
# Helper used from Dockerfile.base to pre-pull the Gemma model into the
# baked-in read-only model store at /opt/ollama-models.
#
# This is only invoked at base-image build time. See ../guestos/ollama.service
# for the runtime service definition.

set -eu

export OLLAMA_MODELS=/opt/ollama-models
export LD_LIBRARY_PATH=/opt/ollama/lib/ollama
# Use the same internal plaintext port that the runtime ollama.service
# binds to. Public access at runtime goes through the TLS-terminating
# stunnel proxy on 11434 (see ollama-tls.service).
export OLLAMA_HOST=127.0.0.1:11435

mkdir -p "${OLLAMA_MODELS}"

/opt/ollama/bin/ollama serve >/tmp/ollama-serve.log 2>&1 &
OLLAMA_PID=$!
trap 'kill "${OLLAMA_PID}" 2>/dev/null || true; wait "${OLLAMA_PID}" 2>/dev/null || true' EXIT

# Wait for the server to come up.
for i in $(seq 1 60); do
    if curl -fs "http://${OLLAMA_HOST}/" >/dev/null 2>&1; then
        break
    fi
    if [ "${i}" = 60 ]; then
        echo "ollama server failed to start within 60s" >&2
        cat /tmp/ollama-serve.log >&2 || true
        exit 1
    fi
    sleep 1
done

/opt/ollama/bin/ollama pull gemma3:1b

# Sanity-check that the model is usable offline.
/opt/ollama/bin/ollama list | grep -q '^gemma3:1b '
