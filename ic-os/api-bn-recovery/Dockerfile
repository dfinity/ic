FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/ic/bin /opt/ic/share \
    /data/ic_registry_local_store \
    /data/acme

# Copy binaries (built externally via Bazel)
COPY ic-boundary /opt/ic/bin/ic-boundary
COPY ic-registry-replicator /opt/ic/bin/ic-registry-replicator

# Copy NNS public key
COPY nns_public_key.pem /opt/ic/share/nns_public_key.pem

# Copy entrypoint
COPY entrypoint.sh /opt/ic/bin/entrypoint.sh
RUN chmod +x /opt/ic/bin/entrypoint.sh \
    /opt/ic/bin/ic-boundary \
    /opt/ic/bin/ic-registry-replicator

# HTTP, HTTPS, ic-boundary metrics, replicator metrics
EXPOSE 8080 443 9090 9092

# Persistent data
VOLUME ["/data/ic_registry_local_store", "/data/acme", "/certs"]

ENTRYPOINT ["/opt/ic/bin/entrypoint.sh"]
