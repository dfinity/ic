FROM ubuntu:20.04

RUN apt -yq update && \
    apt -yq install --no-install-recommends git curl wget ca-certificates sudo

RUN groupadd -g 1000 ubuntu && useradd -ms /bin/bash -u 1000 -g 1000 ubuntu && \
    groupadd -g 1001 runner && useradd -ms /bin/bash -u 1001 -g 1001 runner && \
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER runner

# Install rustup and cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    /bin/bash -c "source $HOME/.cargo/env && rustup default stable"

CMD ["/bin/bash"]
