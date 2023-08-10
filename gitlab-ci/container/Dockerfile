# https://hub.docker.com/_/ubuntu
# focal-20230605
FROM ubuntu@sha256:554e40b15453c788ec799badf0f1ad05c3e5c735b53f940feb8f27cf2ec570c5
ENV TZ=UTC

COPY --chown=0700 ./gitlab-ci/container/files/known_hosts /etc/ssh/ssh_known_hosts

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

ARG mkcert_version=1.4.4
ARG mkcert_sha=6d31c65b03972c6dc4a14ab429f2928300518b26503f58723e532d1b0a3bbb52
RUN curl -fsSL https://github.com/FiloSottile/mkcert/releases/download/v${mkcert_version}/mkcert-v${mkcert_version}-linux-amd64 -o /usr/local/bin/mkcert && \
    echo "$mkcert_sha /usr/local/bin/mkcert" | sha256sum --check && \
    chmod +x /usr/local/bin/mkcert

ARG bazelisk_sha=8b739ac23a189b70d51a98041e90ba16f6559d5f991d83bbc031c740f8796310
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.12.2/bazelisk-linux-amd64 -o /usr/bin/bazel && \
    echo "$bazelisk_sha /usr/bin/bazel" | sha256sum --check && \
    chmod 777 /usr/bin/bazel

ARG nvm_version=v0.39.1
ENV NVM_DIR=/opt/nvm
RUN mkdir $NVM_DIR && \
    curl --fail https://raw.githubusercontent.com/nvm-sh/nvm/${nvm_version}/install.sh -sSf | bash

ARG sw_node_version=18
RUN . /opt/nvm/nvm.sh && \
    nvm install ${sw_node_version}

RUN groupadd -g 1000 ubuntu && useradd -ms /bin/bash -u 1000 -g 1000 ubuntu

# CI before script requires sudo
RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Pre-populate the Bazel installation for root
COPY .bazelversion /tmp/bazel/
RUN cd /tmp/bazel && touch WORKSPACE  && bazel version

COPY ./gitlab-ci/container/files/generate-bazel-completion.sh /tmp/
RUN USE_BAZEL_VERSION=$(tail -1 /tmp/bazel/.bazelversion) /tmp/generate-bazel-completion.sh
RUN echo "source /etc/bash_completion.d/bazel" >>/etc/bash.bashrc

# Add cocogitto
ARG COCOGITTO_VERSION="5.4.0"
ARG COCOGITTO_BIN="/usr/local/bin/cog"
ARG COCOGITTO_OUT="cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz"
RUN curl -fsSL "https://github.com/cocogitto/cocogitto/releases/download/${COCOGITTO_VERSION}/cocogitto-${COCOGITTO_VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar -xz -C "/usr/local/bin" && \
    rm "/usr/local/bin/LICENSE" && \
    echo "26a64a7ace621a0c8aabf9305987b91aa9e84c35db949e8809d4a97ae977fa34  ${COCOGITTO_BIN}" | shasum -a 256 -c -

USER ubuntu

# Set PATH for ubuntu user
ENV PATH=/ic/bin:/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:$PATH
ENV PYTHONPATH=/ic/gitlab-ci/src:/ic/gitlab-ci/src/dependencies:$PYTHONPATH

# Pre-populate the Bazel installation for ubuntu
RUN cd /tmp/bazel && bazel version

# Add Rust/Cargo support
ARG rust_version=1.71.0
RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown

# Install all python requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN sudo pip3 install --ignore-installed -r /tmp/requirements.txt
RUN sudo pip3 install pre-commit

# Add buf
ARG BUF_BIN="/usr/local/bin/buf"
ARG BUF_VERSION="1.25.1"
RUN curl -sSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" -o "${BUF_BIN}" && \
    echo "3e013b7b7d204ee0ca2952da076fd3fd6e014d11aa92e6262a4343bd61747f34  ${BUF_BIN}" | shasum -a 256 -c - && \
    chmod +x "${BUF_BIN}"

# Add zshrc generated from zsh-newuser-install (option 2)
COPY --chown=ubuntu:ubuntu ./gitlab-ci/container/files/zshrc /home/ubuntu/.zshrc

# Add yq
ARG YQ_BIN="/usr/local/bin/yq"
ARG YQ_VERSION="4.34.1"
RUN curl -sSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" -o "${YQ_BIN}" && \
    echo "c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a  ${YQ_BIN}" | shasum -a 256 -c - && \
    chmod +x "${YQ_BIN}"

COPY ./gitlab-ci/container/TAG /home/ubuntu/.DFINITY-TAG

WORKDIR /
USER 0

RUN mv /usr/bin/docker /usr/bin/docker-bin
COPY ./gitlab-ci/container/files/containers.conf /etc/containers/containers.conf
COPY ./gitlab-ci/container/files/docker.sh /usr/bin/docker
COPY ./gitlab-ci/container/files/entrypoint.sh /entrypoint.sh

# Add mold linker
ARG MOLD_BIN="/usr/local/bin/mold"
ARG MOLD_VERSION=2.0.0
RUN curl -sSL "https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-$(uname -m)-linux.tar.gz" | tar -C /usr/local --strip-components=1 -xzf - && \
    echo "4d17d89e0c6a7c4c08ba5e0d3bbe9fd9c01ba227212307e157722c910e9a88be  ${MOLD_BIN}" | shasum -a 256 -c - && \
    ln -sf "${MOLD_BIN}" "$(realpath /usr/bin/ld)"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
