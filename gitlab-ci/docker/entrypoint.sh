#!/usr/bin/env bash

DOCKER_SOCKET=/var/run/docker.sock
DOCKER_GROUP=docker
KVM_DEV=/dev/kvm
KVM_GROUP=kvm

eval $(cat /entrypoint_user)

grep -q $DOCKER_GROUP /etc/group
DOCKER_GREP_RET=$?
grep -q $KVM_GROUP /etc/group
KVM_GREP_RET=$?

if [ -S $DOCKER_SOCKET ] && [ $DOCKER_GREP_RET -ne 0 ]; then
    DOCKER_GID=$(stat -c '%g' $DOCKER_SOCKET)

    sudo addgroup --gid $DOCKER_GID $DOCKER_GROUP
    sudo usermod -aG $DOCKER_GROUP $USER
fi

if [ -c $KVM_DEV ] && [ $KVM_GREP_RET -ne 0 ]; then
    KVM_GID=$(stat -c '%g' $KVM_DEV)

    sudo addgroup --gid $KVM_GID $KVM_GROUP
    sudo usermod -aG $KVM_GROUP $USER
fi

exec gosu $USER "$@"
