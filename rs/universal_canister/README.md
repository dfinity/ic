Universal Canister
==================

The implementation of the universal canister is in `/impl`, while the library that
tests use to interface with the universal canister is in `/lib`.

To make modifications to the universal canister:

```shell
# Build the Wasm binary
bazel build //rs/universal_canister/impl:universal_canister

# Find the optimized canister binary
ls -l $(bazel info output_path)/k8-opt/bin/rs/universal_canister/impl/universal_canister.opt.wasm

# Move optimized WASM into the /lib directory.
mv $(bazel info output_path)/k8-opt/bin/rs/universal_canister/impl/universal_canister.opt.wasm universal_canister/lib/src/universal-canister.wasm

# When done making changes and you're ready to push a change,
# you need to update the checksum in /lib.
sha256sum universal_canister/lib/src/universal-canister.wasm

# Take the output of the command above and paste it as the value of UNIVERSAL_CANISTER_WASM_SHA256
# in lib/src/lib.rs
```

Note that the universal canister's implementation is temporarily using its `Cargo.lock` file
and is excluded from being built in the top-level workspace. In the future, it will be
integrated into the top-level workspace and its `Cargo.lock` will be merged.
