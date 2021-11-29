FROM rust:bullseye as builder-00

ARG GITHUB_TOKEN

ARG RELEASE=master

WORKDIR /var/tmp

RUN \
  (curl -H "Authorization: token ${GITHUB_TOKEN}" -L https://api.github.com/repos/dfinity-lab/dfinity/tarball/${RELEASE} | tar xz --strip-components=1) && \
  cd rs/rosetta-api && \
  cargo build --release --package ic-rosetta-api --bin ic-rosetta-api

FROM debian:bullseye-slim

ARG RELEASE

LABEL RELEASE=${RELEASE}

WORKDIR /root

COPY --from=builder-00 \
  /var/tmp/rs/target/release/ic-rosetta-api \
  /usr/local/bin/

COPY --from=builder-00 \
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
