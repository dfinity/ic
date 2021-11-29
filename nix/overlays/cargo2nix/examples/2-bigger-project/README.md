# A bigger project

This is a larger `bin` project which requires some dependencies from Crates.io
and is compiled using the latest release of Rust.

## Introduction

This example assumes that you have already read through the [Hello World]
project and have your machine set up with Nix and `cargo2nix`. If this is not
the case, it is strongly recommended that you follow that guide first.

[Hello World]: ../1-hello-world/README.md

Let's begin by creating another Cargo crate called `bigger-project` which
depends on some crates from Crates.io, which in turn require some non-Rust
system dependencies.

## Generating the Cargo project

As described in the previous example, the canonical way to generate a new binary
project with Cargo is to run `cargo new <name>`. However, this requires us to
have some version of the Rust toolchain installed on our system. If Cargo isn't
present on your machine, you can use `nix-shell` to drop into a temporary shell
with Cargo present, like so:

```bash
nix-shell -p cargo
```

Now that we're inside this shell, let's create the `bigger-project` crate we
wish to build:

```bash
cargo new bigger-project
```

Since [Cargo 0.26.0](https://github.com/rust-lang/cargo/pull/5029), the default
project type should be `--bin` if unspecified. You should see the following
output in your terminal:

```text
     Created binary (application) `bigger-project` package
```

This should create a new directory called `bigger-project` containing a mostly
empty `Cargo.toml` and `src/main.rs` file. Change into that directory with `cd`
and replace the existing contents of `src/main.rs` with the following Rust code:

```rust
//! A simple HTTP client using `reqwest`.

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let res = reqwest::get("https://hyper.rs").await?;

    println!("Status: {}", res.status());

    let body = res.text().await?;

    println!("Body:\n\n{}", body);

    Ok(())
}
```

Then, add the following lines to the `[dependencies]` table of the `Cargo.toml`:

```toml
reqwest = "0.10"
tokio = { version = "0.2", features = ["macros"] }
```

As you might be able to tell by now, the `bigger-project` crate depends on both
[`reqwest`] and [`tokio`], providing a simple asynchronous HTTP client. By
default, `reqwest` relies on the [`native-tls`] crate for SSL support, which
requires certain system dependencies depending on the host platform.
Specifically:

* On Linux and NixOS, we depend on OpenSSL (via the [`openssl`] crate).
* On macOS, we depend on Secure Transport (via the [`security-framework`]
  crate).

[`reqwest`]: https://github.com/seanmonstar/reqwest
[`tokio`]: https://github.com/tokio-rs/tokio
[`native-tls`]: https://github.com/sfackler/rust-native-tls
[`openssl`]: https://github.com/sfackler/rust-openssl
[`security-framework`]: https://github.com/kornelski/rust-security-framework

As we will see shortly, the required system dependencies will be magically
injected into the build by `cargo2nix` using the `packageOverrides` argument for
`makePackageSet'` without needing any extra work, but we will get into what that
means later on.

For now, let's focus on wrapping our project with `cargo2nix`!

## Wrapping with cargo2nix

The process for wrapping up our crate with `cargo2nix` should be identical to
that of the Hello World project from earlier.

### Generating a Cargo.nix

Like the previous example, we generate a `Cargo.lock` and `Cargo.nix` for our
crate by running the two commands below:

```bash
cargo generate-lockfile
cargo2nix -f
```

Pretty smooth sailing so far.

### Creating a default.nix

Let's create a new file called [`default.nix`] and declare a function with the
following arguments:

[`default.nix`]: ./default.nix

```nix
{
  system ? builtins.currentSystem,
  nixpkgsMozilla ? builtins.fetchGit {
    url = https://github.com/mozilla/nixpkgs-mozilla;
    rev = "50bae918794d3c283aeb335b209efd71e75e3954";
  },
  cargo2nix ? builtins.fetchGit {
    url = https://github.com/tenx-tech/cargo2nix;
    ref = "v0.8.3";
  },
}:
```

This should be identical to what we did in the Hello World project from earlier.
Likewise, we define the function body with almost identical contents as well:

```nix
let
  rustOverlay = import "${nixpkgsMozilla}/rust-overlay.nix";
  cargo2nixOverlay = import "${cargo2nix}/overlay";

  pkgs = import <nixpkgs> {
    inherit system;
    overlays = [ rustOverlay cargo2nixOverlay ];
  };

  rustPkgs = pkgs.rustBuilder.makePackageSet' {
    rustChannel = "stable";
    packageFun = import ./Cargo.nix;
    # packageOverrides = pkgs: pkgs.rustBuilder.overrides.all; # Implied, if unspecified
  };
in
  rustPkgs.workspace.bigger-project {}
```

Again, we import Nixpkgs using our `nixpkgsMozilla` and `cargo2nix` overlays
and build the `Cargo.nix` for the project with the `rustBuilder.makePackageSet'`
function. The only real difference between the Hello World project and
this new project is that we are building `rustPkgs.workspace.bigger-project`
this time. As before, you can review the full `default.nix` file in its entirety
[here](./default.nix).

You might have noticed that we did not specify any external dependencies to be
used in our build, such as `openssl` or `darwin.apple_sdk.frameworks.Security`.
This is because the `cargo2nix` overlay provides a collection of _crate
overrides_ for many popular Crates.io dependencies by default, tucked away in
`rustBuilder.overrides.all`. If you're curious, you can view our existing
library of provided crate overrides in [overlay/overrides.nix].

[overlay/overrides.nix]: ../../overlay/overrides.nix

`rustBuilder.overrides.all` is a list, so you can always add your own custom
overrides by appending `++ [ myOverride1 myOverride2 ]` to the end. We won't
delve into how custom overrides work in this example, but you should at least be
aware that the option exists.

> Side note: if you'd like to submit more crate overrides for default inclusion
> in the next version of `cargo2nix`, [feel free to open a pull request]!

[feel free to open a pull request]: ./../../CONTRIBUTING.md

Save the `default.nix` file and quit. Your `cargo2nix` project is ready for
building!

## Building

To compile the `bigger-project` binary with Nix, simply run:

```bash
nix-build
```

This will create a `result` symlink in the current directory with the following
structure:

```text
/nix/store/97k0hg8r3641pyqwy07h92mpyn3p3dps-crate-bigger-project-0.1.0
├── .cargo-info
├── bin
│   └── bigger-project
├── lib
│   └── .link-flags
└── nix-support
    └── propagated-build-inputs
```

Running the `bigger-project` binary will print the following output to the
screen:

```text
$ ./result/bin/hello-world
Status: 200 OK
Body:

<!doctype html>
<html>
  <head>
# lots more HTML here...
```

Now that we're getting the hang of building crates with `cargo2nix`, let's
create a small crate workspace and compile some Cargo tests in the next example.
