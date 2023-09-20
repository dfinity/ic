#!/usr/bin/env bash

set -eEuo pipefail

cd "$(git rev-parse --show-toplevel)"

# print sha of relevant files
sha256sum gitlab-ci/container/Dockerfile* gitlab-ci/container/files/* requirements.txt .bazelversion typescript/service-worker/.nvmrc | sha256sum | cut -d' ' -f1
