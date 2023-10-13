# Installation

## PocketIC Binary

Download the latest PocketIC binary for your platform:

```bash
# Linux
curl -sLO https://download.dfinity.systems/ic/307d5847c1d2fe1f5e19181c7d0fcec23f4658b3/openssl-static-binaries/x86_64-linux/pocket-ic.gz
```

```bash
# macOS
curl -sLO https://download.dfinity.systems/ic/307d5847c1d2fe1f5e19181c7d0fcec23f4658b3/openssl-static-binaries/x86_64-darwin/pocket-ic.gz
```

And then run the following to unpack and make `pocket-ic` executable:

```bash
gzip -d pocket-ic.gz
chmod +x pocket-ic
```

On **macOS**, you might have to additionally run
```bash
xattr -dr com.apple.quarantine pocket-ic
```
to bypass the developer verification from Apple.
Alternatively, you can open the `pocket-ic` binary by right clicking on it in the Finder and selecting "Open" from the drop-down menu.
Then, confirm opening this application by clicking "Open" in the dialog that pops up.

By default, PocketIC will always search for the `pocket-ic` binary in the current directory; you can specify another path by setting the `POCKET_IC_BIN` environment variable, for example by prepending it to your `cargo` invocation:

```bash
POCKET_IC_BIN=/path/to/pocket-ic cargo test
```

## PocketIC Library (this crate)

This library is on `crates.io`, so you can install it using cargo. For example, you can add it to your project by running:

```bash
cargo add pocket-ic
```

in your project.
This will add PocketIC as a dependency to your project's `Cargo.toml` file.
Alternatively, you can run 

```bash
cargo install pocket-ic
```

to install the library globally.

Depending on your use case, you may also need the [candid crate](https://crates.io/crates/candid) in your tests. 
