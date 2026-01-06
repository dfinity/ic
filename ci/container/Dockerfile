# https://hub.docker.com/_/ubuntu
# ubuntu:noble-20250910
FROM ghcr.io/dfinity/library/ubuntu@sha256:985be7c735afdf6f18aaa122c23f87d989c30bba4e9aa24c8278912aac339a8d
ENV TZ=UTC

ARG PACKAGE_FILE=ci/container/files/packages.common
COPY ${PACKAGE_FILE} /tmp/
RUN export DEBIAN_FRONTEND=noninteractive && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_FILE)"

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

ARG mkcert_version=1.4.4
ARG mkcert_sha=6d31c65b03972c6dc4a14ab429f2928300518b26503f58723e532d1b0a3bbb52
RUN curl -fsSL https://github.com/FiloSottile/mkcert/releases/download/v${mkcert_version}/mkcert-v${mkcert_version}-linux-amd64 -o /usr/local/bin/mkcert && \
    echo "$mkcert_sha /usr/local/bin/mkcert" | sha256sum --check && \
    chmod +x /usr/local/bin/mkcert

ARG bazelisk_sha=fd8fdff418a1758887520fa42da7e6ae39aefc788cf5e7f7bb8db6934d279fc4
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

# Add cocogitto
ARG COCOGITTO_VERSION="5.4.0"
ARG COCOGITTO_BIN="/usr/local/bin/cog"
ARG COCOGITTO_OUT="cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz"
RUN curl -fsSL "https://github.com/cocogitto/cocogitto/releases/download/${COCOGITTO_VERSION}/cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar -xz -C "/usr/local/bin" && \
    rm "/usr/local/bin/LICENSE" && \
    echo "26a64a7ace621a0c8aabf9305987b91aa9e84c35db949e8809d4a97ae977fa34  ${COCOGITTO_BIN}" | shasum -a 256 -c -

# Add buf
ARG BUF_BIN="/usr/local/bin/buf"
ARG BUF_VERSION="1.46.0"
RUN curl -sSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" -o "${BUF_BIN}" && \
    echo "04c92815f92431bea637d834bee9d2941e979b1c821c59805667c032e2e8fc1f  ${BUF_BIN}" | shasum -a 256 -c - && \
    chmod +x "${BUF_BIN}"

# Add yq
ARG YQ_BIN="/usr/local/bin/yq"
ARG YQ_VERSION="4.34.1"
RUN curl -sSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" -o "${YQ_BIN}" && \
    echo "c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a  ${YQ_BIN}" | shasum -a 256 -c - && \
    chmod +x "${YQ_BIN}"

# Add mold linker
ARG MOLD_BIN="/usr/local/bin/mold"
ARG MOLD_VERSION=2.37.1
RUN curl -sSL "https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-$(uname -m)-linux.tar.gz" | tar -C /usr/local --strip-components=1 -xzf - && \
    echo "98a45fcc651424551f56b8bc4f697ae7ae66930da59b1ef9dfeeaa4da64cb2c6  ${MOLD_BIN}" | shasum -a 256 -c - && \
    ln -sf "${MOLD_BIN}" "$(realpath /usr/bin/ld)"

# Add IC SDK (dfx)
ARG sdk_version=0.25.1
ARG sdk_sha=1e2118e0463aa44fed3a5dee8d638144c67e7b6ee8e0beaf75cfd56687bdb7e7
RUN mkdir -p /tmp/sdk && curl -fsSL https://github.com/dfinity/sdk/releases/download/${sdk_version}/dfx-${sdk_version}-x86_64-linux.tar.gz -o /tmp/sdk/dfx.tar.gz && \
    echo "$sdk_sha /tmp/sdk/dfx.tar.gz" | sha256sum --check && \
    tar -zxf /tmp/sdk/dfx.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/dfx

# Add motoko compiler
ARG motoko_version=0.14.7
RUN curl -fsSL https://github.com/dfinity/motoko/releases/download/${motoko_version}/motoko-linux-x86_64-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

# Create user groups needed for github actions runner
RUN groupadd -g 1001 buildifier && useradd -ms /bin/bash -u 1001 -g 1001 -G ubuntu buildifier && \
    # CI before script requires sudo \
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Add gitconfig
COPY ./ci/container/files/gitconfig /etc/gitconfig

# Install AFLplusplus
ARG AFLPLUSPLUS_RELEASE_VERSION=v4.21c
RUN mkdir -p /afl && \
    chown -R ubuntu:ubuntu /afl && \
    cd /afl && \
    git clone --depth=1 --branch=${AFLPLUSPLUS_RELEASE_VERSION} https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-18 CC=/usr/bin/clang-18 CXX=/usr/bin/clang++-18 make all && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-18 CC=/usr/bin/clang-18 CXX=/usr/bin/clang++-18 make install && \
    mv afl-fuzz afl-showmap  /afl && \
    cd .. && rm -rf AFLplusplus

# Pre-populate the Bazel installation for root
# (note: this is only used for bash completion; the actual bazel version comes from bazelisk)
COPY .bazelversion /tmp/bazel/
RUN cd /tmp/bazel && bazel version

COPY ./ci/container/files/generate-bazel-completion.sh /tmp/
RUN USE_BAZEL_VERSION=$(tail -1 /tmp/bazel/.bazelversion) /tmp/generate-bazel-completion.sh && \
    echo "source /etc/bash_completion.d/bazel" >>/etc/bash.bashrc

COPY ./ci/container/files/containers.conf /etc/containers/containers.conf

USER ubuntu

# Set PATH for ubuntu user
ENV PATH=/ic/bin:/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:$PATH

# Pre-populate the Bazel installation for ubuntu
RUN cd /tmp/bazel && bazel version

# Add Rust/Cargo support
RUN mkdir -p /tmp/rust-version/
COPY rust-toolchain.toml /tmp/rust-version/rust-toolchain.toml
# Read the channel from the toolchain file
RUN sed </tmp/rust-version/rust-toolchain.toml -n 's/^channel = "\(.*\)"$/\1/p' > /tmp/rust-version/version
RUN echo "Rust version:" "$(cat /tmp/rust-version/version)"
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain "$(cat /tmp/rust-version/version)-x86_64-unknown-linux-gnu" --no-modify-path && \
    rustup default "$(cat /tmp/rust-version/version)-x86_64-unknown-linux-gnu" && \
    rustup target add wasm32-unknown-unknown && \
    rustup component add clippy
RUN rm -rf /tmp/rust-version

# Add cargo-audit
ARG CARGO_AUDIT_VERSION=0.22.0
RUN cargo install cargo-audit --version ${CARGO_AUDIT_VERSION}
# Add zshrc generated from zsh-newuser-install (option 2)
COPY --chown=ubuntu:ubuntu ./ci/container/files/zshrc /home/ubuntu/.zshrc

# Read in the build-ci script
COPY ./ci/container/TAG /home/ubuntu/.DFINITY-TAG

WORKDIR /
# Use buildifier (uid 1001) if /entrypoint.sh is overriden
# In GitHub that is the case and we need 1001 and we set it via ARG.
ARG CI_USER="root"
USER $CI_USER
CMD ["/bin/bash"]
