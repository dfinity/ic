#!/usr/bin/env bash

set -eux

echo "${VERSION:-$(git rev-parse --verify HEAD)}"
