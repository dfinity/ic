# https://hub.docker.com/_/ubuntu
# focal-20240216
FROM ubuntu@sha256:48c35f3de33487442af224ed4aabac19fd9bfbd91ee90e9471d412706b20ba73
ENV TZ=UTC

COPY --chmod=0700 ./gitlab-ci/container/files/known_hosts /etc/ssh/ssh_known_hosts

ARG PACKAGE_FILE=gitlab-ci/container/files/packages.common
COPY ${PACKAGE_FILE} /tmp/
RUN export DEBIAN_FRONTEND=noninteractive && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt -yq update && \
    apt -yqq install $(sed -e "s/#.*//" "/tmp/$(basename $PACKAGE_FILE)") && \
    rm "/tmp/$(basename $PACKAGE_FILE)"

ARG motoko_version=0.9.1
RUN curl -fsSL https://github.com/dfinity/motoko/releases/download/${motoko_version}/motoko-linux64-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

ARG buildevents_version=0.6.0
RUN curl -fsSL https://github.com/honeycombio/buildevents/releases/download/v${buildevents_version}/buildevents-linux-amd64 -o /usr/bin/buildevents && \
    chmod +x /usr/bin/buildevents

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    curl -fsSL "https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_20.04/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/devel_kubic_libcontainers_stable.gpg > /dev/null && \
    echo 'deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list && \
    apt -yq update && \
    apt -yqq install --no-install-recommends docker-ce-cli podman buildah zip fuse-overlayfs xtail

# install afl & gsutils deps for bazel-fuzzers
RUN curl -L "https://apt.llvm.org/llvm-snapshot.gpg.key" | apt-key add - && \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main" | tee -a /etc/apt/sources.list.d/llvm.list && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && \
    apt -yq update && \
    apt -yqq install --no-install-recommends lld-18 llvm-18 llvm-18-dev clang-18 libclang-rt-18-dev google-cloud-cli \
    gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

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

ARG sdk_version=0.12.0
ARG sdk_sha=40da56ad27774d5e1b2cbc35f94c17368be8c8da557aca19878940264bd82a0a
RUN mkdir -p /tmp/sdk && curl -fsSL https://github.com/dfinity/sdk/releases/download/${sdk_version}/dfx-${sdk_version}-x86_64-linux.tar.gz -o /tmp/sdk/dfx.tar.gz && \
    echo "$sdk_sha /tmp/sdk/dfx.tar.gz" | sha256sum --check && \
    tar -zxf /tmp/sdk/dfx.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/dfx

ARG mkcert_version=1.4.4
ARG mkcert_sha=6d31c65b03972c6dc4a14ab429f2928300518b26503f58723e532d1b0a3bbb52
RUN curl -fsSL https://github.com/FiloSottile/mkcert/releases/download/v${mkcert_version}/mkcert-v${mkcert_version}-linux-amd64 -o /usr/local/bin/mkcert && \
    echo "$mkcert_sha /usr/local/bin/mkcert" | sha256sum --check && \
    chmod +x /usr/local/bin/mkcert

ARG bazelisk_sha=d28b588ac0916abd6bf02defb5433f6eddf7cba35ffa808eabb65a44aab226f7
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.19.0/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

ARG nvm_version=v0.39.1
ARG dependency_mgmt_nns_dapp_node_version=18.17.1
ARG dependency_mgmt_default_node_version=20
ENV NVM_DIR=/opt/nvm
RUN mkdir $NVM_DIR && \
    curl --fail https://raw.githubusercontent.com/nvm-sh/nvm/${nvm_version}/install.sh -sSf | bash

RUN . /opt/nvm/nvm.sh && \
    nvm install ${dependency_mgmt_nns_dapp_node_version} && \
    nvm install ${dependency_mgmt_default_node_version}

RUN groupadd -g 1000 ubuntu && useradd -ms /bin/bash -u 1000 -g 1000 ubuntu && \
    # needed for github actions runner \
    groupadd -g 1001 buildifier && useradd -ms /bin/bash -u 1001 -g 1001 buildifier && \
    # CI before script requires sudo \
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Add gitconfig
COPY ./gitlab-ci/container/files/gitconfig /etc/gitconfig

# Pre-populate the Bazel installation for root
COPY .bazelversion /tmp/bazel/
RUN cd /tmp/bazel && touch WORKSPACE  && bazel version

COPY ./gitlab-ci/container/files/generate-bazel-completion.sh /tmp/
RUN USE_BAZEL_VERSION=$(tail -1 /tmp/bazel/.bazelversion) /tmp/generate-bazel-completion.sh && \
    echo "source /etc/bash_completion.d/bazel" >>/etc/bash.bashrc

# Add cocogitto
ARG COCOGITTO_VERSION="5.4.0"
ARG COCOGITTO_BIN="/usr/local/bin/cog"
ARG COCOGITTO_OUT="cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz"
RUN curl -fsSL "https://github.com/cocogitto/cocogitto/releases/download/${COCOGITTO_VERSION}/cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar -xz -C "/usr/local/bin" && \
    rm "/usr/local/bin/LICENSE" && \
    echo "26a64a7ace621a0c8aabf9305987b91aa9e84c35db949e8809d4a97ae977fa34  ${COCOGITTO_BIN}" | shasum -a 256 -c -

# Add buf
ARG BUF_BIN="/usr/local/bin/buf"
ARG BUF_VERSION="1.31.0"
RUN curl -sSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" -o "${BUF_BIN}" && \
    echo "a4589eea3afa5f8cda01c3830cdc0112ddd08c32f8b1d45007291fae9fc9bbf4  ${BUF_BIN}" | shasum -a 256 -c - && \
    chmod +x "${BUF_BIN}"

# Add yq
ARG YQ_BIN="/usr/local/bin/yq"
ARG YQ_VERSION="4.34.1"
RUN curl -sSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" -o "${YQ_BIN}" && \
    echo "c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a  ${YQ_BIN}" | shasum -a 256 -c - && \
    chmod +x "${YQ_BIN}"

# Add mold linker
ARG MOLD_BIN="/usr/local/bin/mold"
ARG MOLD_VERSION=2.4.1
RUN curl -sSL "https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-$(uname -m)-linux.tar.gz" | tar -C /usr/local --strip-components=1 -xzf - && \
    echo "4d34b489a0810e71a937103f38e4b6c951abac36b5b60c58bc07b73efa7139cd  ${MOLD_BIN}" | shasum -a 256 -c - && \
    ln -sf "${MOLD_BIN}" "$(realpath /usr/bin/ld)"

# Add kubectl
ARG KUBECTL_BIN="/usr/local/bin/kubectl"
ARG KUBECTL_VERSION="1.22.17"
RUN curl -sSL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o "${KUBECTL_BIN}" && \
    echo "7506a0ae7a59b35089853e1da2b0b9ac0258c5309ea3d165c3412904a9051d48  ${KUBECTL_BIN}" | sha256sum -c - && \
    chmod +x "${KUBECTL_BIN}"

# Install AFLplusplus
ARG AFL_RELEASE_VERSION=v4.21c
RUN mkdir -p /afl && \
    chown -R ubuntu:ubuntu /afl && \
    cd /afl && \
    git clone --depth=1 --branch=${AFL_RELEASE_VERSION} https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-18 CC=/usr/bin/clang-18 CXX=/usr/bin/clang++-18 make all && \
    STATIC=1 LLVM_CONFIG=/usr/bin/llvm-config-18 CC=/usr/bin/clang-18 CXX=/usr/bin/clang++-18 make install && \
    mv afl-fuzz afl-showmap  /afl && \
    cd .. && rm -rf AFLplusplus

RUN mv /usr/bin/docker /usr/bin/docker-bin
COPY ./gitlab-ci/container/files/containers.conf /etc/containers/containers.conf
COPY ./gitlab-ci/container/files/docker.sh /usr/bin/docker
COPY ./gitlab-ci/container/files/entrypoint.sh /entrypoint.sh

USER ubuntu

# Set PATH for ubuntu user
ENV PATH=/ic/bin:/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:$PATH
ENV PYTHONPATH=/ic/ci/src:/ic/ci/src/dependencies:$PYTHONPATH

# Pre-populate the Bazel installation for ubuntu
RUN cd /tmp/bazel && bazel version

# Add Rust/Cargo support
ARG RUST_VERSION=1.80.0
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${RUST_VERSION}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown && \
    rustup component add clippy

# Add cargo-audit
ARG CARGO_AUDIT_VERSION=0.20.0
RUN cargo install cargo-audit --version ${CARGO_AUDIT_VERSION}

COPY ./gitlab-ci/container/TAG /home/ubuntu/.DFINITY-TAG
# Add zshrc generated from zsh-newuser-install (option 2)
COPY --chown=ubuntu:ubuntu ./gitlab-ci/container/files/zshrc /home/ubuntu/.zshrc

WORKDIR /
# Use buildifier (uid 1001) if /entrypoint.sh is overriden
# In GitHub that is the case and we need 1001 and we set it via ARG.
ARG CI_USER="root"
USER $CI_USER
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
