# 20.04
FROM ubuntu:focal-20211006

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y --no-install-recommends install \
      faketime \
      android-sdk-ext4-utils \
      lvm2 \
      dosfstools \
      fakeroot \
      mtools \
      policycoreutils \
      python3

WORKDIR ic-os

COPY hostos .
COPY scripts scripts

ENTRYPOINT ["/bin/bash", "build/build-disk-image.sh"]
