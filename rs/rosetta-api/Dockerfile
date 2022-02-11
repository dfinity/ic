FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ARG RELEASE

LABEL RELEASE=${RELEASE}

WORKDIR /root

COPY ic-rosetta-api /usr/local/bin/ic-rosetta-api

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

ENTRYPOINT ["/usr/local/bin/ic-rosetta-api", "--store-location", "/data"]
