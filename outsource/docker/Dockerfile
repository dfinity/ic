# syntax=docker/dockerfile
# This Dockerfile builds the image used by the outsource machinery.
# It is a fairly barebone Ubuntu image with a few tools like Nix and sccache
# used when remote-building.
#
# NOTE: We pass the UID and the primary group ID of the logged user to make
# sure that permissions within the container (i.e. the 'ubuntu' user) matches
# that of the user on the host.
FROM ubuntu:20.04
LABEL maintainer="IDX <infra@dfinity.org>"

# Set in the docker build to make sure it matches that of the user on the host
# machine. This makes sure volumes can be mounted and owned by the user.
ARG UID
ARG GID

# The nix version
ARG NIX_VERSION=2.3.10

# The nix version
ARG SCCACHE_VERSION=v0.2.15

RUN apt --yes --quiet update && \
    apt --yes --quiet --quiet install \
# used by Nix
git openssh-client xz-utils \
# some must-haves
curl sudo \
# needed by outsource
rsync \
# needed by outsource itself and the icos_deploy script (ansible)
python3 python3-pip \
# needed by the icos_deploy script (ansible)
jq dosfstools mtools rclone \
# linked to at runtime
liblmdb-dev

# Install sccache in /usr/bin/sccache
RUN cd /usr/bin; \
    curl --fail -L \
    https://github.com/mozilla/sccache/releases/download/$SCCACHE_VERSION/sccache-$SCCACHE_VERSION-x86_64-unknown-linux-musl.tar.gz \
    | tar xvz --strip-components=1 "sccache-$SCCACHE_VERSION-x86_64-unknown-linux-musl/sccache" \
    && chmod 0755 /usr/bin/sccache

# Make sure sccache is working
RUN sccache --help

# Add the ubuntu used with the user's UID and primary GID on the host
RUN groupadd --gid ${GID} ubuntu
RUN useradd --create-home --shell /bin/bash --uid ${UID} --gid ${GID} ubuntu
RUN usermod --append --groups sudo ubuntu && echo "ubuntu ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Ansible is needed for testnet deploys
RUN /usr/bin/pip3 install ansible==2.10.7

# From here on, and mostly for the Nix installation, we run commands as the user
USER ubuntu

RUN curl --fail -L https://releases.nixos.org/nix/nix-${NIX_VERSION}/install | sh

# For some reason, sourcing bashrc & al doesn't work so we can't source the
# nix.sh script. I didn't have time to figure out why, but this has the same
# effect.
ENV PATH=/home/ubuntu/.nix-profile/bin:$PATH \
    NIX_PROFILES="/nix/var/nix/profiles/default /home/ubuntu/.nix-profile" \
    NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Make sure nix is installed and (at least somewhat working)
RUN nix --help

# Since we mount the Nix store as a volume, the original store will be
# overwritten. So we simply copy the executables and hope that they find the
# dynamic libs to link to. It does work though I'm not 100% sure how (since
# technically the Nix executable links to dynamic libs in the nix store, but
# the store is shadowed by the overlay).
RUN sudo cp $(dirname $(which nix))/* /bin
