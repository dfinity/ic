#!/usr/bin/env bash

set -euo pipefail

# system-tests that use the "local" backend spawn qemu-system-x86_64 processes which need write access to /dev/kvm.
sudo chmod 0666 /dev/kvm

exec "$@"
