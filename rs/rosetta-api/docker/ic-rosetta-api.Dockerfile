FROM rust:1.74-bookworm as builder

ARG RELEASE=master

WORKDIR /var/tmp

COPY \
  ic-fi-1079.tar.gz \
  ic.tar.gz

RUN \
  apt update && \
  apt install -y \
    ca-certificates \
    libsqlite3-0 \
    protobuf-compiler && \
  apt autoremove --purge -y

RUN \
  tar -xf ic.tar.gz --strip-components=1 && \
  cd rs/rosetta-api && \
  cargo build --release --bin ic-rosetta-api

FROM debian:bookworm-slim

ARG RELEASE

LABEL RELEASE=${RELEASE}

WORKDIR /root

COPY --from=builder \
  /var/tmp/rs/target/release/ic-rosetta-api \
  /usr/local/bin/

RUN \
  rm -rf \
    /tmp/* \
    /var/lib/apt/lists/* \
    /var/tmp/*

ENTRYPOINT ["/usr/local/bin/ic-rosetta-api", "--store-location", "/data", "--store-type", "sqlite"]
