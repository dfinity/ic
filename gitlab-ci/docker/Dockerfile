FROM ubuntu:20.04

ARG rust_version=1.52.1
# make sure the motoko_version corresponds to the same version in nix/sources.json
ARG motoko_version=0.5.10
ARG sdk_version=0.7.7

# The image expects the following volumes mounted from the host:
# /cache - holding the sccache artifacts
# /cargo - is the CARGO_HOME, holding cargo binaries and cloned repos
# /builds/git - a read only volume with the git repository which should be built

ENV TZ=UTC

# The kvm group id must match the id on the host machines.
# On our machines [Ubuntu 20.04] the ID is 108. Set it up here
# so that other package installation don't nab the same group ID.
RUN groupadd -g 108 kvm

# Ditto for docker groups.
RUN groupadd -g 998 docker-998
RUN groupadd -g 1003 docker-1003

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && \
    apt -yqq install --no-install-recommends \
        git openssh-client curl xz-utils time parallel net-tools \
        apt-transport-https ca-certificates curl gnupg lsb-release && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg  && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null  && \
    apt -yq update && \
    apt -yqq install --no-install-recommends \
        build-essential pkg-config libssl-dev llvm-10-dev llvm-dev liblmdb-dev clang-10 cmake libbz2-dev \
        lldb libclang-10-dev liblz4-dev librocksdb-dev libsnappy-dev libzstd-dev vim emacs nano jq \
        zip unzip rclone rsync bc csmith gcc lld lld-10 libc++-10-dev protobuf-compiler libprotobuf-dev \
        libcsmith-dev \
        sqlite3 libsqlite3-dev \
        qemu-system-x86 ovmf \
        iproute2 \
        dosfstools mtools fakeroot faketime android-sdk-ext4-utils policycoreutils \
        python3 python3-requests python3-pip python3-gflags python3-cbor \
        shellcheck sudo docker-ce-cli \
        asciidoctor plantuml graphviz cpio && gem install asciidoctor-diagram rouge

# Add the `ubuntu` user, and the required folders
RUN useradd -ms /bin/bash -u 1000 ubuntu && \
    mkdir -p /home/ubuntu && \
    chown -R ubuntu.ubuntu /home/ubuntu && \
    mkdir -p /cargo /cargo_target /builds /builds/dfinity-lab && \
    chown -R 1000.1000 /cargo /cargo_target /builds /builds/dfinity-lab

# Add the ubuntu user to kvm and give sudo access. Sudo is needed to run `ip tun` commands to create a virtual network for e2e tests.
RUN usermod -a -G kvm ubuntu && usermod -a -G sudo ubuntu && usermod -a -G docker-998 ubuntu && usermod -a -G docker-1003 ubuntu && echo "ubuntu ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Install sccache in /usr/bin/sccache
RUN V=v0.2.15; cd /usr/bin; \
    curl --fail -L https://github.com/mozilla/sccache/releases/download/$V/sccache-$V-x86_64-unknown-linux-musl.tar.gz | tar xvz --strip-components=1 "sccache-$V-x86_64-unknown-linux-musl/sccache" && \
    chmod 0755 /usr/bin/sccache

# Install buildevents in /usr/bin/
RUN cd /usr/bin; \
    curl --fail -L -o buildevents "https://github.com/honeycombio/buildevents/releases/download/v0.5.0/buildevents-linux-amd64" && \
    chmod 0755 /usr/bin/buildevents

RUN cd /tmp; \
    curl --fail -sL https://raw.githubusercontent.com/mszostok/codeowners-validator/master/install.sh | sh -s v0.6.0 && \
    cp ./bin/codeowners-validator /usr/bin && \
    chmod 0755 /usr/bin/codeowners-validator

# Install Rust and Cargo in /opt
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    CARGO_TARGET_DIR=/cargo_target \
    ZSTD_LIB_DIR=/usr/lib \
    PROTOC=/usr/bin/protoc \
    PROTOC_INCLUDE=/usr/include \
    PATH=/opt/cargo/bin:$PATH

RUN curl --fail https://sh.rustup.rs -sSf \
        | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown && \
    chown -R ubuntu.ubuntu ${RUSTUP_HOME} ${CARGO_HOME}

# Cargo maintains a local cache of the registry index and of git checkouts of crates at CARGO_HOME.
# Set this to a host-mounted volume.
ENV CARGO_HOME=/cargo

# Note that motoko is automatically published to our CDN on every release.
# Unpack to a temporary directory instead of directly into /usr/bin, to avoid messing up the perms of /usr/bin
# e.g. docker: exec: "/usr/bin/dumb-init": stat /usr/bin/dumb-init: permission denied: unknown.
RUN mkdir -p /tmp/install && curl --fail -L \
    "https://download.dfinity.systems/motoko/${motoko_version}/x86_64-linux/motoko-${motoko_version}.tar.gz" \
    | tar -xz -C /tmp/install && chmod +x /tmp/install/moc && mv /tmp/install/moc /usr/bin/moc && rm -rf /tmp/install

RUN mkdir -p /tmp/install && curl --fail -L \
    "https://download.dfinity.systems/sdk/dfx/${sdk_version}/x86_64-linux/dfx-${sdk_version}.tar.gz" \
    | tar -xz -C /tmp/install && chmod +x /tmp/install/dfx && mv /tmp/install/dfx /usr/bin/dfx && rm -rf /tmp/install

# Install IC CDK optimizer
RUN curl --fail -sL https://download.dfinity.systems/cdk-rs/5807d2f7b523f630eddd69acd4b245a8b129eff9/ic-cdk-optimizer-linux-amd64.gz -o /opt/cargo/bin/ic-cdk-optimizer.gz && \
    gunzip /opt/cargo/bin/ic-cdk-optimizer.gz && \
    chmod 0755 /opt/cargo/bin/ic-cdk-optimizer

# Install IDL2json: https://github.com/dfinity-lab/idl2json
RUN curl --fail -sL https://download.dfinity.systems/idl2json/bcb27ac567eba7a7c14c9d70aedd3fb777af281b/idl2json-linux-amd64.gz -o - \
    | gunzip > /usr/bin/idl2json && \
    chmod 0755 /usr/bin/idl2json

# dumb-init takes care to properly handle and forward signals as they are received (e.g. Ctrl+C or SIGSEGV)
# ENTRYPOINT with dumb-init is set further down in the Dockerfile
RUN curl --fail -L -o /usr/bin/dumb-init \
        https://github.com/Yelp/dumb-init/releases/download/v1.2.5/dumb-init_1.2.5_x86_64 && \
    chmod +x /usr/bin/dumb-init

RUN /usr/bin/pip3 install ansible==2.10.7 gitpython pre-commit honeycomb-beeline junit-xml paramiko python-gitlab libhoney

USER 1000

# Adds the GitHub and GitLab signatures to known_hosts
# so that `git pull` calls don't require user approval
RUN mkdir --mode=0700 /home/ubuntu/.ssh && \
    printf "# github.com:22 SSH-2.0-babeld-c34a939f\n|1|TtiEWekp4T2g6QFM8DnKUWYsXdw=|Vfo6utz2X8h5YSK2kjy1NrrVDQs= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|fzEEbwQf9OkgzIxxgASmZp9L0Ec=|rty0872nCLuKDCsl3fuGSEmS81U= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|k6eNETvB6tZStZlifmM3Y6qrmkw=|AWemKhMqEjFAPf/125ARU2xLpmk= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n|1|/5OjzdrCg7KAVMh9Q3xfH0OvqLY=|9Yl++Oih6L3ENgUjQCx3uqFPvfc= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf\n# gitlab.com:22 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\n" >> /home/ubuntu/.ssh/known_hosts && \
    chmod 0600 /home/ubuntu/.ssh/known_hosts

WORKDIR /

ENTRYPOINT ["/usr/bin/dumb-init", "--"] 
