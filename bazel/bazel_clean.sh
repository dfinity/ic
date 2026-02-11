#!/usr/bin/env bash

set -x

bazel clean --expunge
bazel shutdown
sudo rm -fr $HOME/.cache/bazel*
sudo rm -fr $HOME/.cache/buildbuddy*
sudo rm -fr /tmp/zig-cache/*
rm -fr /private/var/tmp/_bazel_*
