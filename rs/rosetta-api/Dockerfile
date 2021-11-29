FROM debian:bullseye-slim

WORKDIR /root

COPY target/release/ic-rosetta-api /usr/local/bin/ic-rosetta-api

COPY log_config.yml /root

RUN \
  apt update && \
  apt install -y \
    ca-certificates \
    libsqlite3-0 && \
  apt autoremove --purge -y && \
  rm -rf \
    /tmp/* \
    /var/lib/apt/lists/* \
    /var/tmp/*

ENTRYPOINT ["/usr/local/bin/ic-rosetta-api", "--store-location", "/data", "--store-type", "sqlite"]
