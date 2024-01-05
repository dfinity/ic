#!/usr/bin/env bash

set -x

bazel clean --expunge
bazel shutdown
sudo rm -fr $HOME/.cache/bazel*
rm -fr /private/var/tmp/_bazel_*
