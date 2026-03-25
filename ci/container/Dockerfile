# https://hub.docker.com/_/ubuntu
# ubuntu:noble-20250910
FROM ghcr.io/dfinity/library/ubuntu@sha256:985be7c735afdf6f18aaa122c23f87d989c30bba4e9aa24c8278912aac339a8d as base

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

## Because the container is used for both CI and development, we need to have a user that matches the UID of the runner (1001) and a user that matches the UID of ubuntu (1000)
RUN groupadd -g 1001 buildifier && useradd -ms /bin/bash -u 1001 -g 1001 -G ubuntu buildifier && \
    # both buildifier and ubuntu users need to be able to access root permissions
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Install a version of google-android-platform-tools-installer with e2fsdroid
RUN export DEBIAN_FRONTEND=noninteractive && \
    mkdir e2fsdroid && \
    cd e2fsdroid && \
    curl -fsSLO http://mirrors.kernel.org/ubuntu/pool/multiverse/g/google-android-installers/google-android-platform-tools-installer_35.0.0+1710437545-3build2_amd64.deb && \
    curl -fsSLO http://mirrors.kernel.org/ubuntu/pool/multiverse/g/google-android-installers/google-android-licenses_1710437545-3build2_all.deb && \
    dpkg-deb -R google-android-platform-tools-installer_35.0.0+1710437545-3build2_amd64.deb contents && \
    cd contents && \
    sed -i 's/35.0.0/33.0.2/' DEBIAN/control DEBIAN/postinst && \
    sed -i '/Version/ s/$/+downgraded/' DEBIAN/control && \
    rm usr/share/google-android-platform-tools-installer/platform-tools_r35.0.0-linux.zip.sha1 && \
    echo "6bf4f747ad929b02378b44ce083b4502d26109c7  platform-tools_r33.0.2-linux.zip" > usr/share/google-android-platform-tools-installer/platform-tools_r33.0.2-linux.zip.sha1 && \
    find . -type f -not -path "./DEBIAN/*" -exec md5sum {} + | sort -k 2 | sed 's/\.\/\(.*\)/\1/' > DEBIAN/md5sums && \
    cd .. && \
    dpkg-deb -b contents/ downgraded.deb && \
    apt -yqq install ./downgraded.deb ./google-android-licenses_1710437545-3build2_all.deb && \
    apt-mark hold google-android-platform-tools-installer && \
    cd .. && \
    rm -rf e2fsdroid

ARG bazelisk_sha=22e7d3a188699982f661cf4687137ee52d1f24fec1ec893d91a6c4d791a75de8
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

# Add mold linker - required because it is 6x faster than ld
ARG MOLD_BIN="/usr/local/bin/mold"
ARG MOLD_VERSION=2.37.1
RUN curl -sSL "https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-$(uname -m)-linux.tar.gz" | tar -C /usr/local --strip-components=1 -xzf - && \
    echo "98a45fcc651424551f56b8bc4f697ae7ae66930da59b1ef9dfeeaa4da64cb2c6  ${MOLD_BIN}" | shasum -a 256 -c - && \
    ln -sf "${MOLD_BIN}" "$(realpath /usr/bin/ld)"

# Add motoko compiler
ARG motoko_version=0.16.3
RUN curl -fsSL https://github.com/dfinity/motoko/releases/download/${motoko_version}/motoko-linux-x86_64-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

# install cargo with the ubuntu user
USER ubuntu
ENV PATH=/ic/bin:/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:$PATH
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN RUST_VERSION=$(sed -n 's/^channel = "\(.*\)"$/\1/p' /tmp/rust-toolchain.toml) && \
    echo "Rust version: $RUST_VERSION" && \
    curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain "${RUST_VERSION}-x86_64-unknown-linux-gnu" --no-modify-path && \
    rustup default "${RUST_VERSION}-x86_64-unknown-linux-gnu" && \
    rustup target add wasm32-unknown-unknown && \
    rustup component add clippy && \
    sudo rm /tmp/rust-toolchain.toml

# Add cargo-audit
ARG CARGO_AUDIT_VERSION=0.22.0
RUN cargo install cargo-audit --version ${CARGO_AUDIT_VERSION}

# switch back to root user after cargo install so that we have permissions to install additional packages
USER root
WORKDIR /
CMD ["/bin/bash"]

FROM base as build

# Install packages only needed fro ci
ARG PACKAGE_CI_FILE=ci/container/files/packages.ci
COPY ${PACKAGE_CI_FILE} /tmp/
RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_CI_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_CI_FILE)"

# Install AFLplusplus for fuzzing
# LLVM is only a build time dependency now since we link the fuzzer lib from the hermetic toolchain directly
ARG AFLPLUSPLUS_RELEASE_VERSION=v4.35c
ARG LLVM_VERSION=21
RUN curl -L "https://apt.llvm.org/llvm-snapshot.gpg.key" | apt-key add - && \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_VERSION} main" | tee -a /etc/apt/sources.list.d/llvm.list && \
    apt -yq update && \
    apt -yqq install --no-install-recommends lld-${LLVM_VERSION} llvm-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev clang-${LLVM_VERSION} libclang-rt-${LLVM_VERSION}-dev && \
    mkdir -p /afl && \
    chown -R ubuntu:ubuntu /afl && \
    cd /afl && \
    git clone --depth=1 --branch=${AFLPLUSPLUS_RELEASE_VERSION} https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-${LLVM_VERSION} CC=/usr/bin/clang-${LLVM_VERSION} CXX=/usr/bin/clang++-${LLVM_VERSION} make all && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-${LLVM_VERSION} CC=/usr/bin/clang-${LLVM_VERSION} CXX=/usr/bin/clang++-${LLVM_VERSION} make install && \
    mv afl-fuzz afl-showmap  /afl && \
    cd .. && rm -rf AFLplusplus

USER buildifier

FROM base as dev

# Add zshrc generated from zsh-newuser-install (option 2)
COPY --chown=ubuntu:ubuntu ./ci/container/files/zshrc /home/ubuntu/.zshrc

# Install additional packages for development but not needed on CI:
ARG PACKAGE_DEV_FILE=ci/container/files/packages.dev
COPY ${PACKAGE_DEV_FILE} /tmp/
RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_DEV_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_DEV_FILE)"

# Install GitHub CLI `gh` following: https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian
RUN mkdir -p -m 755 /etc/apt/keyrings \
	&& out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
	&& cat $out | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& mkdir -p -m 755 /etc/apt/sources.list.d \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null

USER ubuntu
