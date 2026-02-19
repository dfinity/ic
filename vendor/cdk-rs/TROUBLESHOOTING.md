# Troubleshooting

## I was linked here by a Cargo error!

If your Cargo command produces the following error:

```
error: failed to select a version for `ic-cdk-executor`.
    ... required by package `yourcrate v0.1.0 (/Users/you/yourcrate)`
versions that meet the requirements `0.1.0` are: 0.1.0

the package `ic-cdk-executor` links to the native library `ic-cdk async executor`, but it conflicts with a previous package which links to `ic-cdk async executor` as well:
package `ic-cdk-executor v1.0.0`
    ... which satisfies dependency `ic-cdk-executor = "^1.0.0` of package `someothercrate v0.1.0`
Only one package in the dependency graph may specify the same links value. This helps ensure that only one copy of a native library is linked in the final binary. Try to adjust your dependencies so that only one package uses the `links = "ic-cdk async executor"` value. For more information, see https://doc.rust-lang.org/cargo/reference/resolver.html#links.

failed to select a version for `ic-cdk-executor` which could resolve this conflict
```

You have two incompatible versions of `ic-cdk` (or `ic-cdk-timers`) in your dependency tree. There are two common reasons for this.

First, a dependency may be using an older (or newer) version of the CDK. Many versions of `ic-cdk` are compatible with each other, but versions 0.17 and earlier are incompatible with version 0.18, and 0.18 is incompatible with 0.19 or later. `ic-cdk-timers` does not have non-semver compatibility and any two versions are incompatible. In either case you will have to wait for those dependencies to update, or patch them yourself.

Second, a dependency may be using a nominally compatible version of the CDK, but you are using a GitHub prerelease of the CDK with `ic-cdk = { git =`. Git dependencies are automatically incompatible with everything, even if nothing changed. You will need to create a [patch table](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html) that replaces all CDK dependencies with a Git dependency at the same commit.

You can find the dependencies responsible with the command `cargo tree -i ic-cdk`.
