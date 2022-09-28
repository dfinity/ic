FROM dfinity/ic-build@sha256:f552fcdeffdc6586be608b9a04e0c16bef5aa844e8985f1d3e1db5de0f24384e

ENV CARGO_TARGET_DIR=/workspaces/ic/rs/target
ENV RUSTUP_HOME=/home/ubuntu/.rustup CARGO_HOME=/home/ubuntu/.cargo

# more command line tools that might be useful for users
RUN sudo env DEBIAN_FRONTEND=noninteractive bash -c 'apt -y update && apt -y install wget diffoscope linux-tools-common apt-file'

COPY docker-entrypoint.sh /
RUN chmod +x docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sleep", "infinity"]
