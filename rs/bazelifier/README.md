This is a tool that turns a crate into a BUILD file.

## Usage

```
$ bazel run //rs/bazelifier -- path/to/some/Cargo.toml
```

## Limitations

- Can't translate target specific dependencies. The tool will warn you when it encounters any.
- Can't always distinguish between regular and proc macro dependencies. You may have to move some of the entries, but `bazel` will tell you what to do in such cases.
- Will not overwrite an existing BUILD.bazel, since the one it generates is not guaranteed to be correct.
- Doesn't run buildifier to format the generated file afterward, you'll have to do it manually.
- Doesn't generate a tests section.
- Doesn't modify the workspace file. If a new external dependency is needed, you'll have to do it manually.
