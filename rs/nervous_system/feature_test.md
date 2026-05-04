# Compile-time feature toggling for preview-stage features

Crates under `rs/nervous_system`, `rs/nns`, and `rs/sns` should follow the convention
described in this document for providing a secondary compilation target that emits
code marked with `#[cfg(feature = "test")]` and omits code marked with `#[cfg(not(feature = "test"))]`
in Rust.

## Use case

For example, if a canister release must urgently be rolled out, but the feature
`FEATURE_NAME` is not yet ready for release (although it is already merged into the
master branch), then one may resort to the following workaround:

```rust
// TODO(NNS1-ABCD): This feature is currently available only as a preview.
// TODO(NNS1-ABCD): Make this feature is generally available by deleting
// TODO(NNS1-ABCD): this chunk of code (and updating callers).
#[cfg(feature = "test")]
fn FEATURE_NAME_is_enabled() -> bool {
    true
}
#[cfg(not(feature = "test"))]
fn FEATURE_NAME_is_enabled() -> bool {
    false
}
```

## Propagating test-feature requirements through the dependency tree

Normally, our (production-ready) Rust crates specify just `deps = DEPENDENCIES` in
their corresponding Bazel target, and do not specify `crate_features = ["test"]`.
However, when a rule does specify `crate_features = ["test"]`, then it should also
propagate that requirement to all of its dependencies. This can be achieved by
following the convention in which all Rust crates with `crate_features = ["test"]`
also specify `deps = DEPENDENCIES_WITH_TEST_FEATURES`.

This is to avoid multiple copies of the same crate, each with a different set of
features, from both being used in the same build. Such copies cause problems where
non-interchangeable copies of the "same" type exist within the same crate.

To define `DEPENDENCIES_WITH_TEST_FEATURES`, please follow the convention explained
below.

## Convention

Assume that a crate `foo` has an additional Bazel spec called `foo--test-feature` that
specifies `crate_features = ["test"]`. If `foo` depends on some other crate `bar`, and
there exists `bar--test-feature`, then `foo--test-feature` should depend on `bar--test-feature`,
and **not** `bar`. To make this explicit, each crate's dependencies should be arranged
as follows:

```bazel
BASE_DEPENDENCIES = [
    "abc",                    # Does not support feature "test".
    ...
]
DEPENDENCIES = BASE_DEPENDENCIES + [
    "bar",                    # Compiled without crate_features = ["test"]
    ...
]
DEPENDENCIES_WITH_TEST_FEATURES = BASE_DEPENDENCIES + [
    "bar:bar--test-feature",  # Compiled with crate_features = ["test"]
    ...
]
rust_binary(
    name = "foo",
    deps = DEPENDENCIES,
    ...
)
rust_binary(
    name = "foo",
    crate_features = ["test"],
    deps = DEPENDENCIES_WITH_TEST_FEATURES,
    ...
)
```

Note that adding a `*--test-feature` version of a crate will not make that crate
available on the CDN (so it is unlikely to be released by-accident).
