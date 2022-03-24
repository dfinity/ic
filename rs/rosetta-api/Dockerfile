FROM ubuntu:20.04

ARG RELEASE

LABEL RELEASE=${RELEASE}

RUN \
  apt update && \
  apt install -y \
    ca-certificates \
    libsqlite3-0 && \
  apt autoremove --purge -y && \
  rm -rf \
    /tmp/* \
    /var/lib/apt/lists/* \
    /var/tmp/* && \
  useradd -m rosetta && \
  mkdir /data && \
  chown rosetta:rosetta /data

COPY ic-rosetta-api /usr/local/bin/ic-rosetta-api

COPY --chown=rosetta:rosetta log_config.yml /home/rosetta

USER rosetta

WORKDIR /home/rosetta

ENTRYPOINT ["/usr/local/bin/ic-rosetta-api", "--store-location", "/data"]
