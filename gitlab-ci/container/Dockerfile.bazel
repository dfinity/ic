# https://hub.docker.com/_/ubuntu
# focal-20230301
FROM ubuntu@sha256:3626dff0d616e8ee7065a9ac8c7117e904a4178725385910eeecd7f1872fc12d

ARG USE_BAZEL_VERSION=invalid
ENV TZ=UTC

COPY --chown=0700 ./gitlab-ci/container/files/known_hosts /etc/ssh/ssh_known_hosts

RUN export DEBIAN_FRONTEND=noninteractive && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && apt -yqq install  \
    curl build-essential git gnupg node-json5 uuid-dev zsh clang \
    # GitLab CI \
    sudo gosu jq rclone \
    # Test \
    rsync \
    # RUST \
    gcc lld pkg-config libssl-dev libunwind-dev libusb-1.0-0-dev libsqlite3-dev zlib1g-dev libclang-10-dev protobuf-compiler llvm liblmdb-dev\
    # IC-OS \
    python3 python-is-python3 python3-pip fakeroot android-sdk-ext4-utils cryptsetup-bin zstd lsb-release grub-efi-amd64-bin libsystemd-dev faketime dosfstools libselinux-dev mtools lvm2

ARG motoko_version=0.5.10
RUN curl -fsSL https://download.dfinity.systems/motoko/${motoko_version}/x86_64-linux/motoko-${motoko_version}.tar.gz | tar -xz -C /usr/local/bin && chmod +x /usr/local/bin/moc

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

COPY ./gitlab-ci/container/files/generate-bazel-completion.sh /tmp/
RUN /tmp/generate-bazel-completion.sh
RUN echo "source /etc/bash_completion.d/bazel" >>/etc/bash.bashrc

# Pre-populate the Bazel installation for root
RUN bazel version
USER ubuntu

# Pre-populate the Bazel installation for ubuntu
RUN bazel version

# Add Rust/Cargo support
ENV PATH=/home/ubuntu/.cargo/bin:$PATH
ARG rust_version=1.58.1
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown

# Install all python requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --ignore-installed -r /tmp/requirements.txt
RUN pip3 install pre-commit

WORKDIR /
USER 0

RUN mv /usr/bin/docker /usr/bin/docker-bin
COPY ./gitlab-ci/container/files/containers.conf /etc/containers/containers.conf
COPY ./gitlab-ci/container/files/docker.sh /usr/bin/docker
COPY ./gitlab-ci/container/files/entrypoint.sh /entrypoint.sh

# Add mold linker
ARG mold_version=1.11.0
ARG mold_platform="mold-${mold_version}-x86_64-linux"
RUN curl -L "https://github.com/rui314/mold/releases/download/v${mold_version}/${mold_platform}.tar.gz" --output "$mold_platform" && \
    tar xvf "$mold_platform" && \
    mv "${mold_platform}/bin/mold" /usr/bin/mold && \
    rm -rf "$mold_platform"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
