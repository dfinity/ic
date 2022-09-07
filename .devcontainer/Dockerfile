FROM dfinity/ic-build@sha256:ee365109b847d163a46f04d4fb931f472da4c640ca925cb79e82fd7bc92fcb35

ENV CARGO_TARGET_DIR=/workspaces/ic/rs/target
ENV RUSTUP_HOME=/home/ubuntu/.rustup CARGO_HOME=/home/ubuntu/.cargo

# more command line tools that might be useful for users
RUN sudo env DEBIAN_FRONTEND=noninteractive apt -y install wget diffoscope linux-tools-common apt-file

COPY docker-entrypoint.sh /
RUN chmod +x docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sleep", "infinity"]
