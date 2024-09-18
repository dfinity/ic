#!/bin/bash

set -euo pipefail

#TZ=UTC
#ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
#apt-get -y update && apt-get -y upgrade && apt-get -y --no-install-recommends install \
#  ca-certificates \
#  curl \
#  perl

## Download and verify QEMU
#cd /tmp/ && \
#  curl -L -O https://download.qemu.org/qemu-6.2.0.tar.xz && \
#  echo "68e15d8e45ac56326e0b9a4afa8b49a3dfe8aba3488221d098c84698bca65b45  qemu-6.2.0.tar.xz" > qemu.sha256 && \
#  shasum -c qemu.sha256
#
## Download and verify node_exporter
#cd /tmp/ && \
#  curl -L -O https://github.com/prometheus/node_exporter/releases/download/v1.8.1/node_exporter-1.8.1.linux-amd64.tar.gz && \
#  echo "fbadb376afa7c883f87f70795700a8a200f7fd45412532cc1938a24d41078011  node_exporter-1.8.1.linux-amd64.tar.gz" > node_exporter.sha256 && \
#  shasum -c node_exporter.sha256


#
# Second build stage:
# - Compile downloaded archives from first build stage
#
#FROM ubuntu:20.04 AS build

#USER root:root

#TZ=UTC
#ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
## Install QEMU build dependencies
#apt-get -y update && apt-get -y upgrade && apt-get -y --no-install-recommends install \
#    ca-certificates \
#    build-essential \
#    libusb-1.0-0-dev \
#    pkg-config \
#    python3

#    ninja-build \
#    libglib2.0-dev \
#    libpixman-1-dev \

# Configure and compile QEMU
#COPY --from=download /tmp/qemu-6.2.0.tar.xz /tmp/qemu-6.2.0.tar.xz
#RUN cd /tmp/ && \
#    tar xJf qemu-6.2.0.tar.xz && \
#    cd /tmp/qemu-6.2.0 && \
#    ./configure --target-list=x86_64-softmmu --enable-kvm --enable-libusb && \
#    echo "Compiling qemu..." && \
#    make -j 2 >/dev/null 2>&1 && \
#    DESTDIR="/out" ninja -C build install

#
# Third build stage:
# - Download and cache minimal Ubuntu Server 20.04 LTS Docker image.
# - Install and cache upstream packages from built-in Ubuntu repositories.
# - Install compiled packages from the second stage.
#
#FROM ubuntu:20.04

#USER root:root

#ARG CPU_SUPPORT
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export DEBIAN_FRONTEND=noninteractive


# For the prod image, just use packages.common to define the packages installed
# on target.
# For the dev image, use both "packages.common" and "packages.dev" -- this can
# be set via docker build args (see above).
#ARG PACKAGE_FILES=packages.common
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
#COPY packages.* /tmp/
apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y --no-install-recommends install $(for P in ${PACKAGE_FILES}; do cat /tmp/$P | sed -e "s/#.*//" ; done) && \
    rm /tmp/packages.*

# Install QEMU
#COPY --from=build /out/usr/local/bin/qemu-system-x86_64 /usr/local/bin/
#COPY --from=build /out/usr/local/share/qemu /usr/local/share/qemu

# Install node_exporter
#COPY --from=download /tmp/node_exporter-1.8.1.linux-amd64.tar.gz /tmp/node_exporter-1.8.1.linux-amd64.tar.gz
#RUN cd /tmp/ && \
#    mkdir -p /etc/node_exporter && \
#    tar --strip-components=1 -C /usr/local/bin/ -zvxf node_exporter-1.8.1.linux-amd64.tar.gz node_exporter-1.8.1.linux-amd64/node_exporter && \
#    rm /tmp/node_exporter-1.8.1.linux-amd64.tar.gz
