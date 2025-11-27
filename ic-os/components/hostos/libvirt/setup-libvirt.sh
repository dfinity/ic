#!/bin/bash

set -e

# Create space for libvirt to manage its config

mount --bind /run/libvirt /etc/libvirt

# Set up log directory, because it will not create it alone
mkdir -p /var/log/libvirt/qemu
