# General

All commands should be run from the repository root (`/ic`).

# Rust

After changing Rust code (`*.rs`) follow these steps in order:

1. **Format** using: `rustfmt <MODIFIED_RUST_FILES>`
   where `<MODIFIED_RUST_FILES>` is a space separated list of paths of all modified Rust files.
2. **Lint** using:
   ```
   cargo clippy --all-features <CRATES> -- \
       -D warnings \
       -D clippy::all \
       -D clippy::mem_forget \
       -A clippy::uninlined_format_args
   ```
   where `<CRATES>` is a space separated list of
   `-p <CRATE>` options for all modified crates.
   e.g., `-p ic-crypto -p ic-types` if both were modified.
   Run a single clippy invocation covering all modified crates.

   To determine the crate name, check the `name` field in the nearest
   ancestor `Cargo.toml` relative to the modified file.

   Fix any linting errors.
3. **Build** the directly affected bazel targets using:
   ```
   TARGETS="$(bazel query 'kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 1))' --keep_going 2>/dev/null)"
   if [ -n "$TARGETS" ]; then
       bazel build $TARGETS
   fi
   ```
   where `<MODIFIED_FILES>` is a space separated list of paths of all modified files.

   Fix all build errors.
4. **Test** the directly affected bazel tests using:
   ```
   TESTS="$(bazel query 'kind(".*_test|test_suite", kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 2)))' --keep_going 2>/dev/null)"
   if [ -n "$TESTS" ]; then
       bazel test $TESTS
   fi
   ```
   (Use a depth of 2 in `rdeps` because tests usually depend on source files indirectly through a `rust_library` for example).
   Fix all test failures.
