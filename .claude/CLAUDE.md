Rust
====

After changing Rust code (`*.rs`) first format the code using:

```
cargo fmt -- <MODIFIED_RUST_FILES>
````

Then check the code for linting errors using:

```
cargo clippy --all-features --workspace --all-targets -- \
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

After code can be built it needs to be tested.

After changing a package under `rs/$PACKAGE` run `bazel test //rs/$PACKAGE`.
