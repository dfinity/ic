This is a tool that turns a crate into a BUILD file.

## Usage

```
bazelifier

USAGE:
    bazelifier [OPTIONS] <CARGO_FILE>

ARGS:
    <CARGO_FILE>    Cargo.toml file to convert

OPTIONS:
    -f, --force      Overwrite any existing BUILD file
    -h, --help       Print help information
    -n, --dry-run    Show the generated file instead of writing it
    -t, --tests      Generate rust_test invocations
```

Example:

```
# show a generated BUILD.bazel file with tests for the crypto crate
$ bazel run bazelifier -- rs/crypto/Cargo.toml -n -t
```

## Limitations

- Can't translate target specific dependencies. The tool will warn you when it encounters any.
- Can't always distinguish between regular and proc macro dependencies. You may have to move some of the entries, but `bazel` will tell you what to do in such cases.
- Doesn't run buildifier to format the generated file afterward. You'll have to do it manually, or let `pre-commit` run buildifier automatically.
- Doesn't modify the workspace file. If a new external dependency is needed, you'll have to do it manually.
