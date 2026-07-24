# General

All commands should be run from the repository root (`/ic`).

Never manually edit `ci/container/TAG`. It is bumped only by the
`container-autobuild.yml` GitHub Actions workflow, which builds the new
dev-container image and pushes it to the registry *before* the tag change
takes effect. Hand-editing it points the tag at an image that was never built
or published, breaking CI for everyone. If the dev container image genuinely
needs to change (e.g. `ci/container/Dockerfile` was edited), let that workflow
bump `TAG` — don't do it in your commit.

# Rust

After changing Rust code (`*.rs`) follow these steps in order:

1. **Format** by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   rustfmt <MODIFIED_RUST_FILES>
   ```
   where `<MODIFIED_RUST_FILES>` is a space separated list of paths of all modified Rust files relative to the root of the repository.
2. **Check** by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   cargo check --all-targets --all-features <CRATES>
   ```
   where `<CRATES>` is the same space separated list of `-p <CRATE>` options as
   used for clippy below. `--all-targets` covers `--tests`, `--benches`,
   `--examples`, and `--bins`, so it also checks test code. This is a fast
   compile-only pass to catch basic errors before the slower clippy/bazel steps.

   Fix any compile errors.
3. **Lint** by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   cargo clippy --all-features <CRATES> -- \
       -D warnings \
       -D clippy::all \
       -D clippy::mem_forget \
       -D clippy::unseparated_literal_suffix \
       -A clippy::uninlined_format_args
   ```
   where `<CRATES>` is a space separated list of
   `-p <CRATE>` options for all modified crates.
   e.g., `-p ic-crypto -p ic-types` if both were modified.
   Run a single clippy invocation covering all modified crates.

   To determine the crate name, check the `name` field in the nearest
   ancestor `Cargo.toml` relative to the modified file.

   Fix any linting errors.
4. **Repin**, if any `Cargo.toml` changed which third-party crate dependency is
   used (added, removed, or version-bumped):

   1. Keep the two builds (Cargo and Bazel) in line: a third-party crate is
      declared in **both** the root `Cargo.toml` (`[workspace.dependencies]`)
      and `bazel/rust.MODULE.bazel` (as a `crate.spec(...)`). If you changed one,
      mirror the change in the other (best effort) so the package, version, and
      features match. Adding a crate to `Cargo.toml` without a matching
      `crate.spec` means Bazel can't resolve `@crate_index//:<crate>`.
   2. Regenerate the `Cargo.Bazel.*.lock` files that pin `@crate_index` for Bazel
      by running the following from the root of the repository:
      ```
      cd "$(git rev-parse --show-toplevel)"
      ./bin/bazel-pin.sh
      ```

   Skip this step entirely if no third-party dependency changed. Without it,
   the build step below fails or builds against a stale crate index.
5. **Build** the directly affected bazel targets by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   TARGETS="$(bazel query 'kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 1))' --keep_going 2>/dev/null)" || true
   if [ -n "$TARGETS" ]; then
       bazel build $TARGETS
   fi
   ```
   where `<MODIFIED_FILES>` is a space separated list of paths of all modified files relative to the root of the repository.

   Fix all build errors.
6. **Test** the directly affected bazel tests by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   TESTS="$(bazel query 'kind(".*_test|test_suite", kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 2))) except attr(tags, "manual", //...)' --keep_going 2>/dev/null)" || true
   if [ -n "$TESTS" ]; then
       bazel test --test_output=errors $TESTS
   fi
   ```
   (Use a depth of 2 in `rdeps` because tests usually depend on source files indirectly through a `rust_library` for example).

   Always run tests, even if they're system-tests, i.e. their label starts with `//rs/tests/`.

   Fix all test failures.

# Bazel

After changing any Bazel file (`BUILD.bazel`, `MODULE.bazel`, `*.bzl`), see
the **check-bazel-files** skill.

# Pull Requests

When asked to create a PR, always create it in draft mode.

When updating a PR prefer to push new commits to the PR branch instead of force-pushing over the existing commits.

After the PR has been created or updated, request a review from the GitHub Copilot bot using:
```
gh api repos/dfinity/ic/pulls/<PULL_REQUEST_NUMBER>/requested_reviewers --method POST --raw-field 'reviewers[]=copilot-pull-request-reviewer[bot]'
```
where `<PULL_REQUEST_NUMBER>` is the number of the Pull Request.