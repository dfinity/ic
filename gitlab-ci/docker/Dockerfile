ARG SRC_IMG_PATH=undefined
FROM ${SRC_IMG_PATH} as src_img

# https://hub.docker.com/_/ubuntu
# focal-20220922
FROM ubuntu@sha256:e722c7335fdd0ce77044ab5942cb1fbd2b5f60d1f5416acfcdb0814b2baf7898

# The image expects the following volumes mounted from the host:
# /cache - holding the cache artifacts
# /cargo - is the CARGO_HOME, holding cargo binaries and cloned repos
# /builds/git - a read only volume with the git repository which should be built

ENV TZ=UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && \
    apt -yqq install --no-install-recommends git openssh-client curl xz-utils time parallel net-tools \
        apt-transport-https ca-certificates curl gnupg lsb-release && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/Release.key" |  apt-key add - && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/ /" | tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list && \
    apt -yq update && \
    apt -yqq install --no-install-recommends \
        android-sdk-ext4-utils \
        build-essential pkg-config libssl-dev llvm-10-dev llvm-dev liblmdb-dev clang clang-10 cmake libbz2-dev gcc-multilib zlib1g-dev \
        lldb libc-bin libclang-10-dev liblz4-dev librocksdb-dev libsnappy-dev libzstd-dev zstd vim emacs nano jq \
        zip unzip rclone rsync bc csmith gcc lld lld-10 libc++-10-dev libcsmith-dev sqlite3 libsqlite3-dev libselinux-dev libunwind-dev libsystemd-dev uuid-dev \
        qemu-system-x86 ovmf iproute2 dosfstools mtools fakeroot faketime android-sdk-ext4-utils \
        policycoreutils python3 python3-pip python3-gflags python3-cbor pipenv shellcheck \
        sudo docker-ce-cli ripgrep patchelf asciidoctor plantuml graphviz cpio nodejs npm gosu pigz zsh hub less \
        ca-certificates curl git isolinux p7zip-full syslinux xorriso cryptsetup-bin autoconf automake \
        grub-efi-amd64-bin podman buildah && \
    gem install asciidoctor-diagram rouge

# Add the `${USER}` user, and the required folders
ARG USER=ubuntu
ARG UID=1000
RUN useradd -ms /bin/bash -u ${UID} ${USER} && \
    mkdir -p /home/${USER} && \
    chown -R ${UID}.${UID} /home/${USER} && \
    mkdir -p /cargo /cargo_target /builds /builds/dfinity-lab && \
    chown -R ${UID}.${UID} /cargo /cargo_target /builds && \
    chmod +s /usr/sbin/gosu

# Sudo is needed to run `ip tun` commands to create a virtual network for e2e tests
RUN usermod -a -G sudo ${USER} && echo "${USER} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Install Rust and Cargo in /opt
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_TARGET_DIR=/cargo_target \
    ZSTD_LIB_DIR=/usr/lib \
    PROTOC=/usr/protoc/bin/protoc \
    PROTOC_INCLUDE=/usr/protoc/include \
    PATH=/opt/cargo/bin:$PATH

COPY --from=src_img /opt /tmp/src-artifacts
RUN rsync --chmod=755 -rav /tmp/src-artifacts/ /usr && rm -rf /tmp/src-artifacts

# rustup uses $CARGO_HOME to figure out where to install itself
ARG rust_version=1.58.1
ENV CARGO_HOME=/opt/cargo
RUN curl --fail https://sh.rustup.rs -sSf \
        | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown && \
    chown -R ${USER}.${USER} ${RUSTUP_HOME} ${CARGO_HOME}

# cargo-nextest
RUN curl -LsSf https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.36/cargo-nextest-0.9.36-x86_64-unknown-linux-gnu.tar.gz | tar zxf - -C /opt/cargo/bin

ARG nvm_version=v0.39.1
ARG node_version=17
ENV NVM_DIR=/opt/nvm
RUN mkdir $NVM_DIR && \
    curl --fail https://raw.githubusercontent.com/nvm-sh/nvm/${nvm_version}/install.sh -sSf | bash

# CARGO_HOME is also where the crates.io registry and git checkouts are cached.
# We bind mount this on the CI runners, so the image needs to be able to function properly
# even if this directory is empty.
ENV CARGO_HOME=/cargo

# Init for reaping zombies and performing signal forwarding (https://github.com/krallin/tini)
ARG tini_version=0.19.0
RUN curl -fsSL https://github.com/krallin/tini/releases/download/v${tini_version}/tini -o /tini && \
    curl -fsSL https://github.com/krallin/tini/releases/download/v${tini_version}/tini.asc -o /tini.asc && \
    chmod +x /tini
RUN gpg --batch --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 && \
    gpg --batch --verify /tini.asc /tini && chmod +x /tini

# To replace nix-shell loading the python packages required for python-tests and dependencies job
RUN /usr/bin/pip3 install ansible==2.10.7 gitpython pre-commit honeycomb-beeline junit-xml paramiko \
    python-gitlab libhoney termcolor pygithub python-dateutil elasticsearch elasticsearch-dsl freezegun \
    jsonschema mypy pylint pytest-shutil pyyaml xmltodict pytest==5.4.3 codeowners jira toml aenum cvss pytest-cov \
    requests==2.27.1 urllib3==1.26.8

ARG didc_release_date=2022-01-06
RUN curl --fail \
         --location https://github.com/dfinity/candid/releases/download/${didc_release_date}/didc-linux64 \
         --output /usr/bin/didc-linux64 && chmod +x /usr/bin/didc-linux64

RUN . /opt/nvm/nvm.sh && nvm install ${node_version} && npm install -g @vscode/dev-container-cli

USER ${UID}

ENV ROCKSDB_INCLUDE_DIR=/usr/include ROCKSDB_LIB_DIR=/usr/lib ROCKSDB_STATIC=1 \
    SNAPPY_INCLUDE_DIR=/usr/include SNAPPY_LIB_DIR=/usr/lib/x86_64-linux-gnu SNAPPY_STATIC=1 \
    LZ4_INCLUDE_DIR=/usr/include LZ4_LIB_DIR=/usr/lib/x86_64-linux-gnu LZ4_STATIC=1 \
    ZSTD_INCLUDE_DIR=/usr/include ZSTD_LIB_DIR=/usr/lib/x86_64-linux-gnu ZSTD_STATIC=1 \
    Z_INCLUDE_DIR=/usr/include Z_LIB_DIR=/usr/lib/x86_64-linux-gnu Z_STATIC=1 \
    BZ2_INCLUDE_DIR=/usr/include BZ2_LIB_DIR=/usr/lib/x86_64-linux-gnu BZ2_STATIC=1

# Pre-populate the Bazel installation.
RUN USE_BAZEL_VERSION=5.3.2 bazel version

RUN mkdir --mode=0700 /home/${USER}/.ssh
COPY ./files/known_hosts /home/${USER}/.ssh/known_hosts

COPY entrypoint.sh /entrypoint.sh
WORKDIR /

USER 0

RUN mv /usr/bin/docker /usr/bin/docker-bin
COPY containers.conf /etc/containers/containers.conf
COPY docker.sh /usr/bin/docker

RUN echo "USER=${USER}" > /entrypoint_user

ENTRYPOINT ["/tini", "--", "/entrypoint.sh"]
