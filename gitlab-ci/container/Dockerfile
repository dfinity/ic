# https://hub.docker.com/_/ubuntu
# focal-20230605
FROM ubuntu@sha256:554e40b15453c788ec799badf0f1ad05c3e5c735b53f940feb8f27cf2ec570c5
ENV TZ=UTC

COPY --chown=0700 ./gitlab-ci/container/files/known_hosts /etc/ssh/ssh_known_hosts

RUN export DEBIAN_FRONTEND=noninteractive && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && apt -yqq install  \
    curl build-essential git gnupg node-json5 uuid-dev zsh fish clang iproute2 shellcheck \
    # Bitcoin core (for bitcoin adapter integration test) \
    libtool libevent-dev libboost-dev \
    # GitLab CI \
    sudo gosu jq rclone time qemu-system-x86 \
    # Test \
    rsync \
    # RUST \
    gcc lld pkg-config libssl-dev libunwind-dev libusb-1.0-0-dev libsqlite3-dev zlib1g-dev libclang-10-dev protobuf-compiler llvm liblmdb-dev liblzma-dev\
    # IC-OS \
    python3 python-is-python3 python3-pip fakeroot android-sdk-ext4-utils cryptsetup-bin zstd lsb-release grub-efi-amd64-bin libsystemd-dev faketime dosfstools libselinux-dev mtools lvm2

ARG motoko_version=0.9.1
RUN curl -fsSL https://github.com/dfinity/motoko/releases/download/${motoko_version}/motoko-linux64-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

ARG buildevents_version=0.6.0
RUN curl -fsSL https://github.com/honeycombio/buildevents/releases/download/v${buildevents_version}/buildevents-linux-amd64 -o /usr/bin/buildevents && \
    chmod +x /usr/bin/buildevents

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/Release.key" |  apt-key add - && \
    echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/ /" | tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list && \
    apt -yq update && \
    apt -yqq install --no-install-recommends docker-ce-cli podman buildah

ARG sdk_version=0.12.0
ARG sdk_sha=40da56ad27774d5e1b2cbc35f94c17368be8c8da557aca19878940264bd82a0a
RUN mkdir -p /tmp/sdk && curl -fsSL https://github.com/dfinity/sdk/releases/download/${sdk_version}/dfx-${sdk_version}-x86_64-linux.tar.gz -o /tmp/sdk/dfx.tar.gz && \
    echo "$sdk_sha /tmp/sdk/dfx.tar.gz" | sha256sum --check && \
    tar -zxf /tmp/sdk/dfx.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/dfx

ARG bazelisk_sha=8b739ac23a189b70d51a98041e90ba16f6559d5f991d83bbc031c740f8796310
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.12.2/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

RUN groupadd -g 1000 ubuntu && useradd -ms /bin/bash -u 1000 -g 1000 ubuntu

# CI before script requires sudo
RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Pre-populate the Bazel installation for root
COPY .bazelversion /tmp/bazel/
RUN cd /tmp/bazel && touch WORKSPACE  && bazel version

COPY ./gitlab-ci/container/files/generate-bazel-completion.sh /tmp/
RUN USE_BAZEL_VERSION=$(tail -1 /tmp/bazel/.bazelversion) /tmp/generate-bazel-completion.sh
RUN echo "source /etc/bash_completion.d/bazel" >>/etc/bash.bashrc

USER ubuntu

# Set PATH for ubuntu user
ENV PATH=/ic/bin:/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:$PATH
ENV PYTHONPATH=/ic/gitlab-ci/src:/ic/gitlab-ci/src/dependencies:$PYTHONPATH

# Pre-populate the Bazel installation for ubuntu
RUN cd /tmp/bazel && bazel version

# Add Rust/Cargo support
ARG rust_version=1.66.1
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown

# Install all python requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN sudo pip3 install --ignore-installed -r /tmp/requirements.txt
RUN sudo pip3 install pre-commit

# Add buf
ARG BUF_BIN="/usr/local/bin"
ARG BUF_VERSION="1.21.0"
RUN curl -sSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
    -o "${BUF_BIN}/buf" && chmod +x "${BUF_BIN}/buf"

# Add zshrc generated from zsh-newuser-install (option 2)
COPY --chown=ubuntu:ubuntu ./gitlab-ci/container/files/zshrc /home/ubuntu/.zshrc

# Add yq
ARG YQ_BIN="/usr/local/bin/yq"
ARG YQ_VERSION="4.34.1"
RUN curl -sSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" -o "${YQ_BIN}" && \
    echo "c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a  ${YQ_BIN}" | shasum -a 256 -c - && \
    chmod +x "${YQ_BIN}"

WORKDIR /
USER 0

RUN mv /usr/bin/docker /usr/bin/docker-bin
COPY ./gitlab-ci/container/files/containers.conf /etc/containers/containers.conf
COPY ./gitlab-ci/container/files/docker.sh /usr/bin/docker
COPY ./gitlab-ci/container/files/entrypoint.sh /entrypoint.sh

# Add mold linker
ARG mold_version=1.11.0
RUN curl -L --retry 10 --silent --show-error "https://github.com/rui314/mold/releases/download/v${mold_version}/mold-${mold_version}-$(uname -m)-linux.tar.gz" | tar -C /usr/local --strip-components=1 -xzf - && \
    ln -sf /usr/local/bin/mold "$(realpath /usr/bin/ld)"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
