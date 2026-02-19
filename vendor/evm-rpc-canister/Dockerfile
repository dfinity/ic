# Use this with
#
#  docker build -t evm_rpc .
#  or use ./scripts/docker-build
#
# The docker image. To update, run `docker pull ubuntu` locally, and update the
# sha256:... accordingly.
FROM --platform=linux/amd64 ubuntu@sha256:626ffe58f6e7566e00254b638eb7e0f3b11d4da9675088f4781a50ae288f3322 as deps

ENV TZ=UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && \
    apt -yqq install --no-install-recommends curl ca-certificates \
        build-essential pkg-config libssl-dev llvm-dev liblmdb-dev clang cmake jq

# Install Rust and Cargo in /opt
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/cargo \
    PATH=/cargo/bin:$PATH

WORKDIR /evm_rpc

RUN mkdir -p ./scripts
COPY ./scripts/bootstrap ./scripts/bootstrap
COPY ./rust-toolchain.toml ./rust-toolchain.toml

RUN ./scripts/bootstrap

# Pre-build all cargo dependencies. Because cargo doesn't have a build option
# to build only the dependecies, we pretend that our project is a simple, empty
# `lib.rs`. When we COPY the actual files we make sure to `touch` lib.rs so
# that cargo knows to rebuild it with the new content.
COPY Cargo.lock .
COPY Cargo.toml .
COPY e2e/rust/Cargo.toml e2e/rust/Cargo.toml
COPY ./scripts/build ./scripts/build
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && touch src/lib.rs \
    && mkdir -p e2e/rust/src \
    && touch e2e/rust/src/lib.rs \
    && ./scripts/build --only-dependencies \
    && rm -rf src \
    && rm -rf e2e \
    && rm Cargo.toml \
    && rm Cargo.lock

FROM deps as build

COPY . .

RUN touch src/main.rs

RUN ./scripts/build --evm-rpc
RUN sha256sum evm_rpc.wasm.gz

FROM scratch as scratch_evm_rpc
COPY --from=build evm_rpc/evm_rpc.wasm.gz /
