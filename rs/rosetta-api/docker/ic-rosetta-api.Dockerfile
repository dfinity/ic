FROM rust:1.55.0-bullseye as builder

ARG RELEASE=master

WORKDIR /var/tmp

ADD \
  https://github.com/dfinity/ic/archive/${RELEASE}.tar.gz \
  ic.tar.gz

RUN \
  tar -xf ic.tar.gz --strip-components=1 && \
  cd rs/rosetta-api && \
  cargo build --release --bin ic-rosetta-api

FROM debian:bullseye-slim

ARG RELEASE

LABEL RELEASE=${RELEASE}

WORKDIR /root

COPY --from=builder \
  /var/tmp/rs/target/release/ic-rosetta-api \
  /usr/local/bin/

COPY --from=builder \
  /var/tmp/rs/rosetta-api/log_config.yml \
  /root/

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
