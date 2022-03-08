ARG SRC_IMG_PATH=undefined
FROM ${SRC_IMG_PATH} as src_img

FROM ubuntu@sha256:9c152418e380c6e6dd7e19567bb6762b67e22b1d0612e4f5074bda6e6040c64a

# The image expects the following volumes mounted from the host:
# /cache - holding the sccache artifacts
# /cargo - is the CARGO_HOME, holding cargo binaries and cloned repos
# /builds/git - a read only volume with the git repository which should be built

ENV TZ=UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && \
    apt -yqq install --no-install-recommends git openssh-client curl xz-utils time parallel net-tools \
        apt-transport-https ca-certificates curl gnupg lsb-release && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt -yq update && \
    apt -yqq install --no-install-recommends \
        build-essential pkg-config libssl-dev llvm-10-dev llvm-dev liblmdb-dev clang clang-10 cmake libbz2-dev gcc-multilib zlib1g-dev \
        lldb libc-bin libclang-10-dev liblz4-dev librocksdb-dev libsnappy-dev libzstd-dev zstd vim emacs nano jq \
        zip unzip rclone rsync bc csmith gcc lld lld-10 libc++-10-dev libcsmith-dev sqlite3 libsqlite3-dev libselinux-dev libunwind-dev \
        qemu-system-x86 ovmf iproute2 dosfstools mtools fakeroot faketime android-sdk-ext4-utils \
        policycoreutils python3 python3-requests python3-pip python3-gflags python3-cbor shellcheck \
        sudo docker-ce-cli ripgrep patchelf asciidoctor plantuml graphviz cpio nodejs npm gosu pigz && \
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

RUN /usr/bin/pip3 install ansible==2.10.7 gitpython pre-commit honeycomb-beeline junit-xml paramiko python-gitlab libhoney termcolor

ARG didc_release_date=2022-01-06
RUN curl --fail \
         --location https://github.com/dfinity/candid/releases/download/${didc_release_date}/didc-linux64 \
         --output /usr/bin/didc-linux64 \
  && \
    chmod +x /usr/bin/didc-linux64

USER ${UID}

ENV ROCKSDB_INCLUDE_DIR=/usr/include ROCKSDB_LIB_DIR=/usr/lib ROCKSDB_STATIC=1 \
    SNAPPY_INCLUDE_DIR=/usr/include SNAPPY_LIB_DIR=/usr/lib/x86_64-linux-gnu SNAPPY_STATIC=1 \
    LZ4_INCLUDE_DIR=/usr/include LZ4_LIB_DIR=/usr/lib/x86_64-linux-gnu LZ4_STATIC=1 \
    ZSTD_INCLUDE_DIR=/usr/include ZSTD_LIB_DIR=/usr/lib/x86_64-linux-gnu ZSTD_STATIC=1 \
    Z_INCLUDE_DIR=/usr/include Z_LIB_DIR=/usr/lib/x86_64-linux-gnu Z_STATIC=1 \
    BZ2_INCLUDE_DIR=/usr/include BZ2_LIB_DIR=/usr/lib/x86_64-linux-gnu BZ2_STATIC=1


# Adds the GitHub and GitLab signatures to known_hosts so that `git pull` calls don't require user approval
RUN mkdir --mode=0700 /home/${USER}/.ssh && \
    printf "# github.com:22 SSH-2.0-babeld-c34a939f\n|1|TtiEWekp4T2g6QFM8DnKUWYsXdw=|Vfo6utz2X8h5YSK2kjy1NrrVDQs= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|fzEEbwQf9OkgzIxxgASmZp9L0Ec=|rty0872nCLuKDCsl3fuGSEmS81U= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|k6eNETvB6tZStZlifmM3Y6qrmkw=|AWemKhMqEjFAPf/125ARU2xLpmk= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|/5OjzdrCg7KAVMh9Q3xfH0OvqLY=|9Yl++Oih6L3ENgUjQCx3uqFPvfc= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n" >> /home/${USER}/.ssh/known_hosts && chmod 0600 /home/${USER}/.ssh/known_hosts

RUN cargo install cargo-audit --version 0.16.0

COPY entrypoint.sh /entrypoint.sh

# Install config for capsules.
COPY dot_capsules.toml /home/${USER}/.capsules.toml
WORKDIR /

USER 0

RUN echo "USER=${USER}" > /entrypoint_user

ENTRYPOINT ["/tini", "--", "/entrypoint.sh"]
