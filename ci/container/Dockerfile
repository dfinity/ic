# https://hub.docker.com/_/ubuntu
# ubuntu:resolute-20260413
FROM ghcr.io/dfinity/library/ubuntu@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4 as packages

ENV TZ=UTC
RUN export DEBIAN_FRONTEND=noninteractive && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# copy/write config files
ARG PACKAGE_FILE=ci/container/files/packages.common
COPY ${PACKAGE_FILE} /tmp/
COPY ./ci/container/files/gitconfig /etc/gitconfig
COPY ./ci/container/files/containers.conf /etc/containers/containers.conf
RUN echo "[storage]\nrootless_storage_path=\"/tmp/containers\"" > /etc/containers/storage.conf
# marker for scripts to check if they are running in this container
RUN touch /home/ubuntu/.ic-build-container

RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_FILE)"

# Build AFLplusplus in its own stage (off the package installation) so the slow
# compilation is isolated and can run independently; the base stage below only
# copies the resulting binaries. (`make install` puts the executables in
# /usr/local/bin/ and the instrumentation passes/runtime in /usr/local/lib/afl/.)
FROM packages as afl
ARG AFLPLUSPLUS_RELEASE_VERSION=v4.35c
RUN git clone --depth=1 --branch=${AFLPLUSPLUS_RELEASE_VERSION} https://github.com/AFLplusplus/AFLplusplus.git /afl && \
    cd /afl && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config CC=/usr/bin/clang CXX=/usr/bin/clang++ make all && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config CC=/usr/bin/clang CXX=/usr/bin/clang++ make install && \
    rm -rf /afl

FROM packages as base

# Drop troublesome SSH file (Potentially related: Debian #1072221)
RUN rm -f /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf

## The image carries two users so the runtime UID can match the host's:
## - ubuntu (1000): DFINITY devenv
## - buildifier (1001): CI runners and namespace.so devboxes
## All tools are installed as root and usable by all. The extra users are only
## there for convenience to avoid running the image as root.
RUN groupadd -g 1001 buildifier && useradd -ms /bin/bash -u 1001 -g 1001 -G ubuntu buildifier && \
    # both buildifier and ubuntu users need to be able to access root permissions
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

ARG bazelisk_sha=22e7d3a188699982f661cf4687137ee52d1f24fec1ec893d91a6c4d791a75de8
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

# Use lld as the default linker instead of GNU bfd ld (which is ~6x slower).
# For our large Rust debug binaries lld links roughly as fast as eg mold and
# with comparable memory use. Bazel uses its own hermetic (zig/lld) toolchain and
# is unaffected; this only changes the system linker used by cargo builds.
RUN ln -sf "$(command -v ld.lld)" "$(realpath /usr/bin/ld)"

# Add motoko compiler
# This is only used by Cargo; Bazel pulls its own via rules_motoko
# NOTE: keep version in line with rules_motoko
ARG motoko_version=0.16.3
RUN curl -fsSL https://github.com/dfinity/motoko/releases/download/${motoko_version}/motoko-linux-x86_64-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

# Copy the AFLplusplus binaries built in the `afl` stage. `make install` lands
# everything under /usr/local (binaries in bin/, passes/runtime in lib/afl/), so
# copying /usr/local merges those in alongside the tools installed above.
COPY --from=afl /usr/local /usr/local

# Install rustup proxies system-wide as root:
# - Binaries land in /opt/cargo/bin/ owned by root, world-readable.
# - The toolchain (incl. targets/components) lives in /ic/rust-toolchain.toml
#   and gets fetched on the first `cargo` invocation.
# - CARGO_HOME/RUSTUP_HOME are only set for the install step; runtime users
#   fall back to their default $HOME/.{cargo,rustup} for per-user state.
ENV PATH=/ic/bin:/opt/cargo/bin:$PATH
RUN curl --fail https://sh.rustup.rs -sSf \
    | env CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup \
      sh -s -- -y --default-toolchain none --no-modify-path \
    && rm -rf /opt/rustup

WORKDIR /
CMD ["/bin/bash"]

FROM base as build

USER buildifier

FROM build as dev

# The package installation below needs root; the `build` stage switched to the
# buildifier user, so switch back to root for the setup steps.
USER root

# Add GitHub CLI repository to get the latest version
RUN mkdir -p -m 755 /etc/apt/keyrings \
	&& out=$(mktemp) && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o "$out" \
	&& cat $out | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& mkdir -p -m 755 /etc/apt/sources.list.d \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null

# Install additional packages for development but not needed on CI:
ARG PACKAGE_DEV_FILE=ci/container/files/packages.dev
COPY ${PACKAGE_DEV_FILE} /tmp/
RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_DEV_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_DEV_FILE)"

# Add zshrc generated from zsh-newuser-install (option 2)
COPY ./ci/container/files/zshrc /etc/zsh/zshrc

USER ubuntu
