FROM rust:1.55.0-bullseye

ARG RELEASE=master

LABEL RELEASE=${RELEASE}

WORKDIR /var/tmp

ADD \
  https://github.com/dfinity/ic/archive/${RELEASE}.tar.gz \
  ic.tar.gz

RUN \
  apt update && \
  apt install -y \
    cmake && \
  cargo install ic-cdk-optimizer && \
  tar -xf ic.tar.gz --strip-components=1 && \
  cd rs && \
  cargo build --target wasm32-unknown-unknown --release --bin ledger-canister && \
  ic-cdk-optimizer -o target/wasm32-unknown-unknown/release/ledger-canister.wasm target/wasm32-unknown-unknown/release/ledger-canister.wasm
