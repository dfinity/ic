#! /usr/bin/env bash

bazel_targets=(
    "//rs/sns/testing:sns-testing-init"
    "//rs/sns/testing:sns-testing"
    # TODO: remove targets below once the suggested way to get them is changed
    # to downloading them from CDN
    "//rs/sns/cli:sns"
    "//rs/pocket_ic_server:pocket-ic-server"
)

bazel_root="$(bazel info workspace)"
bin_dir="$PWD/bin"
mkdir -p "$bin_dir"

for target in "${bazel_targets[@]}"; do
    bazel build "$target"
    # We assume that bazel target has a single output file which should be the case
    # for targets like 'rust_binary'
    bazel_binary_path="$(bazel cquery "$target" \
        --output=starlark --starlark:expr="target.files.to_list()[0].path")"
    cp -f "$bazel_root/$bazel_binary_path" "$bin_dir/"
done

export PATH="$bin_dir:$PATH"
