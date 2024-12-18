#!/usr/bin/env bash
set -eux
BAZEL_VERSION=$(bazel version | awk '/^Build label:/ {print $NF}')
bazel-source-file() {
    curl -fsSL "https://raw.githubusercontent.com/bazelbuild/bazel/$BAZEL_VERSION/$1"
}
exec 1>/etc/bash_completion.d/bazel
bazel-source-file "scripts/bazel-complete-header.bash"
bazel-source-file "scripts/bazel-complete-template.bash"
bazel help completion
