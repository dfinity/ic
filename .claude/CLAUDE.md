Dev Container
=============

Building and testing this repository requires being in the dev container since it provides required dependencies.

Entering the dev container can be done using:

`ci/container/container-run.sh`

Individual commands can also be run in the dev container using:

`ci/container/container-run.sh COMMAND`

Alternatively, in VS Code the Dev Containers extension should be used which automatically loads `.devcontainer/devcontainer.json`.


Rust
====

After changing Rust code (`*.rs`) first format the code using `cargo fmt`.

Then check the code for linting errors using:

```
cargo clippy --locked --all-features --workspace --all-targets --keep-going -- \
    -D warnings \
    -D clippy::all \
    -D clippy::mem_forget \
    -C debug-assertions=off \
    -A clippy::uninlined_format_args
```

Fix any linting errors before continuing with building and testing.


Building
--------

Rust code is built using both `cargo build` and Bazel.

After changing a package under `rs/$PACKAGE` run `bazel build //rs/$PACKAGE`.


Changing crate dependencies
---------------------------

If crate dependencies need to be changed or added:

1. First modify the `Cargo.toml` local to the package.
2. If a crate is used by multiple packages add it to the workspace `Cargo.toml` in the root of the repo and reference it in the `Cargo.toml` local to the package using `{ workspace = true }`.
3. Add the crate to `bazel/rust.MODULE.bazel`.
4. Run a `cargo check` such that the `Cargo.lock` files get updated.
5. Run `bin/bazel-pin.sh --force` to sync `Cargo.lock` with `Cargo.Bazel.json.lock`.


Testing
=======

After code can be build it needs to be tested.

After changing a package under `rs/$PACKAGE` run `bazel test //rs/$PACKAGE`.

Tests under `rs/tests` which are defined using the `system_test` bazel macro are end-to-end tests which are called system-tests. These tests are comprehensive but also slow and harder to debug. So run them last or wait for GitHub Actions to run them on your Pull Request.