FROM ubuntu:20.04

RUN apt -yq update && \
    apt -yq install --no-install-recommends git curl wget ca-certificates sudo build-essential jq xxd

RUN groupadd -g 1001 runner && useradd -ms /bin/bash -u 1001 -g 1001 runner && \
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER runner

# Set PATH for runner user
ENV PATH=/ic/bin:/home/runner/.cargo/bin:/home/runner/.local/bin:$PATH

# Install rustup and cargo
ARG RUST_VERSION=1.79.0
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${RUST_VERSION}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu

CMD ["/bin/bash"]
