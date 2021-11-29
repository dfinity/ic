
Background
==========

The IC functionality is hidden behind the `dfn_macro` `query` and `update` methods.
These macros rely on Cargo.toml having `dfn` and `dfn-core` dependencies present in the project.

Installation
============

Install the Wasm platform

```bash
rustup target add wasm32-unknown-unknown
```

To be able to generate flamegraphs as a regular user, the following command should be executed as root (once per booting)

```bash
echo "-1" | sudo tee /proc/sys/kernel/perf_event_paranoid
```

Running
=======

To build and run the `.wasm` file, it's necessary to build `drun` and then the `.wasm` file and supply the correct `.wasm` file to `drun`
The following steps can be used the achieve the above.

```
cd ../../../rs && cargo build --release
cd -
cargo build --release
flamegraph /usr/bin/time ../../../rs/target/release/drun --config ic.toml messages.txt
```

For convenience, all these steps are placed in a `Makefile`, so a standard `make` in this directory is enough

