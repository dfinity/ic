#!/bin/bash

set -e

# Create space for libvirt to manage its config

mount --bind /run/libvirt /etc/libvirt
