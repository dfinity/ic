# Hacking

Enter the Dev Container to build and test the IC using:
```
ci/container/container-run.sh
```

Alternatively use the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) VS Code extension.

Check your code using:
```
./ci/scripts/rust-lint.sh
```
Or run the commands in that script, like `cargo clippy`, individually.

Build and test your code using bazel - this command runs all tests except for system_tests (which cannot be run locally):
```
bazel test //... --test_tag_filters=-system_test
```
Don't run system-tests if you're not in the DFINITY network since they require infrastructure only available there.
